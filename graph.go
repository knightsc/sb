package sb

// Vertex for
type Vertex int64

// type Vertex struct {
// 	Data interface{}
// }

// Edge for
type Edge struct {
	X, Y *Vertex
}

// Graph for
type Graph struct {
	V map[*Vertex]struct{}
	E map[*Edge]struct{}
}

// NewGraph creates and returns a pointer to a new Graph.
func NewGraph() *Graph {
	return &Graph{
		V: make(map[*Vertex]struct{}),
		E: make(map[*Edge]struct{}),
	}
}

// AddEdge creates the Edge specified by xy and adds it to the graph.
func (g *Graph) AddEdge(x *Vertex, y *Vertex) {
	// e := Edge{u, v}
}
