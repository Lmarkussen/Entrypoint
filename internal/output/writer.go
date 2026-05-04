package output

import (
	"os"

	"entrypoint/internal/core"
	"entrypoint/internal/ui"
)

type Writer struct {
	file *os.File
}

type Manager struct {
	full                   *Writer
	success                *Writer
	redactSuccessPasswords bool
}

func NewWriter(path string) (*Writer, error) {
	writer := &Writer{}
	if path == "" {
		return writer, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	writer.file = file
	return writer, nil
}

func NewManager(fullPath, successPath string, redactSuccessPasswords bool) (*Manager, error) {
	full, err := NewWriter(fullPath)
	if err != nil {
		return nil, err
	}

	success, err := NewWriter(successPath)
	if err != nil {
		_ = full.Close()
		return nil, err
	}

	return &Manager{
		full:                   full,
		success:                success,
		redactSuccessPasswords: redactSuccessPasswords,
	}, nil
}

func (w *Writer) WriteLine(line string) error {
	if w.file == nil {
		return nil
	}
	_, err := w.file.WriteString(line)
	return err
}

func (m *Manager) WriteFull(line string) error {
	if m == nil || m.full == nil {
		return nil
	}
	return m.full.WriteLine(line)
}

func (m *Manager) WriteSuccessFinding(finding core.Finding) error {
	if m == nil || m.success == nil || !finding.Success {
		return nil
	}
	return m.success.WriteLine(ui.SuccessLogLine(finding, m.redactSuccessPasswords))
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	if err := m.full.Close(); err != nil {
		_ = m.success.Close()
		return err
	}
	return m.success.Close()
}

func (w *Writer) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}
