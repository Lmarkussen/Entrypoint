package runner

import (
	"context"
	"sync"

	"entrypoint/internal/core"
)

type Config struct {
	Targets   []core.Target
	Creds     []core.Credential
	Modules   []core.Module
	Options   core.Options
	OnFinding func(core.Finding)
}

type task struct {
	module core.Module
	target core.Target
}

func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Modules) == 0 {
		return nil
	}

	moduleByName := make(map[string]core.Module, len(cfg.Modules))
	for _, mod := range cfg.Modules {
		moduleByName[mod.Name()] = mod
	}

	tasks := make(chan task)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range tasks {
				runModuleCheck(ctx, cfg, job)
			}
		}()
	}

	for _, target := range cfg.Targets {
		mod, ok := moduleByName[target.Service]
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			close(tasks)
			wg.Wait()
			return ctx.Err()
		case tasks <- task{module: mod, target: target}:
		}
	}

	close(tasks)
	wg.Wait()
	return ctx.Err()
}

func runModuleCheck(ctx context.Context, cfg Config, job task) {
	findings := core.NormalizeAndCollapseFindings(job.module.Check(ctx, job.target, cfg.Creds, cfg.Options))
	for _, finding := range findings {
		if cfg.OnFinding != nil {
			cfg.OnFinding(finding)
		}
	}
}
