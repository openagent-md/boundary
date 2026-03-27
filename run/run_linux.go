//go:build linux

package run

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/openagent-md/boundary/config"
	"github.com/openagent-md/boundary/landjail"
	"github.com/openagent-md/boundary/nsjail_manager"
)

func Run(ctx context.Context, logger *slog.Logger, cfg config.AppConfig) error {
	switch cfg.JailType {
	case config.NSJailType:
		return nsjail_manager.Run(ctx, logger, cfg)
	case config.LandjailType:
		return landjail.Run(ctx, logger, cfg)
	default:
		return fmt.Errorf("unknown jail type: %s", cfg.JailType)
	}
}
