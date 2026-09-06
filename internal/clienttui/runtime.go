package clienttui

import (
	"context"
	"errors"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/TONresistor/tonnet-messenger/internal/client"
)

func Run(ctx context.Context, instance *client.Client, input io.Reader, output io.Writer) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	model := newModel(sessionCtx, clientBackend{instance})
	_, err := tea.NewProgram(model, tea.WithContext(sessionCtx), tea.WithInput(input), tea.WithOutput(output)).Run()
	cancel()
	closeErr := instance.Close()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		err = nil
	}
	return errors.Join(err, closeErr)
}
