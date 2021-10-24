package heartbeat

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"
)

const discardLimit int64 = 128 * 1024

type URLHeartbeat struct {
	url string
}

func NewURLHeartbeat(url string) *URLHeartbeat {
	return &URLHeartbeat{
		url: url,
	}
}

func (b *URLHeartbeat) Beat(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", b.url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer cleanupBody(resp.Body)

	return nil
}

// Does cleanup of HTTP response in order to make it reusable by keep-alive
// logic of HTTP client
func cleanupBody(body io.ReadCloser) {
	io.Copy(ioutil.Discard, &io.LimitedReader{
		R: body,
		N: discardLimit,
	})
	body.Close()
}
