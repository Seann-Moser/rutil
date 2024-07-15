package epm

import "context"

type HandlerManager interface {
	Init(r context.Context)
}
