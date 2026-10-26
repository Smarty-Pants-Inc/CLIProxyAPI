package logging

// WithHomeRequestLogClientForTest scopes the existing queue seam for external
// integration tests that import the real middleware. It is not in production builds.
func WithHomeRequestLogClientForTest(client homeRequestLogClient, run func()) {
	previous := currentHomeRequestLogClient
	defer func() { currentHomeRequestLogClient = previous }()
	currentHomeRequestLogClient = func() homeRequestLogClient { return client }
	run()
}
