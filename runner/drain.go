package runner

// Drain finishes the current command before leaving the pool. It never cancels work.
func (r *Runner) Drain() { r.setDraining() }
