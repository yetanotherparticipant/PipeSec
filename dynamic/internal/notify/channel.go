package notify

import "github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"

type Channel interface {
	Send(msg string, findings []dynscan.Finding)
}
