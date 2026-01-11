// SPDX-FileCopyrightText: 2025 Paulo Almeida <almeidapaulopt@gmail.com>
// SPDX-License-Identifier: MIT

package dashboard

import (
	"net/http"

	"github.com/yichenchong/tsdproxy-cloudflare/internal/consts"
	"github.com/yichenchong/tsdproxy-cloudflare/internal/model"

	"github.com/a-h/templ"
	datastar "github.com/starfederation/datastar/sdk/go"
)

const (
	chanSizeSSEQueue = 0

	EventAppend EventType = iota
	EventMerge
	EventMergeMessage
	EventRemoveMessage
	EventScript
	EventUpdateSignals
)

// sseClient represents an SSE connection
type (
	EventType int
	sseClient struct {
		channel chan SSEMessage
	}

	SSEMessage struct {
		Comp    templ.Component
		Message string
		Type    EventType
	}
)

// Handler for the `/stream` endpoint
func (dash *Dashboard) streamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")

		sse := datastar.NewSSE(w, r)

		// Create a new client
		client := &sseClient{
			channel: make(chan SSEMessage, chanSizeSSEQueue),
		}

		// Register client
		dash.mtx.Lock()
		dash.sseClients[sessionID] = client
		dash.mtx.Unlock()

		dash.Log.Info().Msg("New Client connected")
		// Ensure client is removed when disconnected
		defer dash.removeSSEClient(sessionID)

		go func() {
			dash.renderList(client.channel)
			dash.updateUser(r, client.channel)
		}()

		var err error

		// Send messages to the client
	LOOP:
		for {
			select {
			case <-r.Context().Done():
				break LOOP
			case message := <-client.channel:
				switch message.Type {
				case EventAppend:
					err = sse.MergeFragmentTempl(
						message.Comp,
						datastar.WithMergeMode(datastar.FragmentMergeModeAppend),
						datastar.WithSelector("#proxy-list"),
					)

				case EventMerge:
					err = sse.MergeFragmentTempl(
						message.Comp,
					)

				case EventMergeMessage:
					err = sse.MergeFragments(message.Message)

				case EventRemoveMessage:
					err = sse.RemoveFragments(message.Message)

				case EventScript:
					err = sse.ExecuteScript(message.Message)

				case EventUpdateSignals:
					err = sse.MergeSignals([]byte(message.Message))
				}
			}

			if err != nil {
				dash.Log.Error().Err(err).Msg("Error sending message to client")
				break LOOP
			}
		}
	}
}

func (dash *Dashboard) updateUser(r *http.Request, ch chan SSEMessage) {
	username := r.Header.Get(consts.HeaderUsername)
	displayName := r.Header.Get(consts.HeaderDisplayName)
	profilePicURL := r.Header.Get(consts.HeaderProfilePicURL)

	signals := `{user_username: '` + username +
		`', user_displayName: '` + displayName +
		`', user_profilePicUrl: '` + profilePicURL + `'}`

	ch <- SSEMessage{
		Type:    EventUpdateSignals,
		Message: signals,
	}
}

func (dash *Dashboard) removeSSEClient(name string) {
	dash.mtx.Lock()

	if client, ok := dash.sseClients[name]; ok {
		delete(dash.sseClients, name)
		close(client.channel)
	}
	dash.mtx.Unlock()

	dash.Log.Info().Msg("Client disconnected")
}

func (dash *Dashboard) streamProxyUpdates() {
	for event := range dash.pm.SubscribeStatusEvents() {
		dash.mtx.RLock()
		for _, sseClient := range dash.sseClients {
			switch event.Status {
			case model.ProxyStatusInitializing:
				dash.renderProxy(sseClient.channel, event.ID, EventAppend)
				dash.streamSortList(sseClient.channel)

			case model.ProxyStatusStopped:
				sseClient.channel <- SSEMessage{
					Type:    EventRemoveMessage,
					Message: "#" + event.ID,
				}

			default:
				dash.renderProxy(sseClient.channel, event.ID, EventMerge)
			}
		}
		dash.mtx.RUnlock()
	}
}

func (dash *Dashboard) streamSortList(channel chan SSEMessage) {
	channel <- SSEMessage{
		Type:    EventScript,
		Message: "sortList()",
	}
}
