// mtrace: lightweight metadata-source -> security-sink candidate extractor for Go K8s controllers.
// Stage 1: metadata source anchors (Labels/Annotations/OwnerReferences/Name + Get* getters)
// Stage 2: intra-function def-use propagation to sinks (resource lookup, mutation, admission decision)
// M2 rule: admission-handler decisions where the metadata-ABSENT branch allows without an identity check.
// Stdlib only (go/ast). Usage: mtrace <repo-dir> > candidates.json
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var metaFields = map[string]string{"Labels": "Label", "Annotations": "Annotation", "OwnerReferences": "OwnerReference"}
var metaGetters = map[string]string{"GetLabels": "Label", "GetAnnotations": "Annotation", "GetOwnerReferences": "OwnerReference", "GetName": "Name"}
var workloadKinds = map[string]bool{"Pod": true, "Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "CronJob": true, "ReplicaSet": true, "PodTemplateSpec": true}

type Candidate struct {
	Score        int    `json:"score"`
	MType        string `json:"m_type"`
	Pattern      string `json:"pattern"`
	MetadataType string `json:"metadata_type"`
	MetadataKey  string `json:"metadata_key"`
	ResourceType string `json:"resource_type"`
	SourceLoc    string `json:"source_location"`
	SourceExpr   string `json:"source_expr"`
	Function     string `json:"function"`
	SinkLoc      string `json:"sink_location"`
	SinkExpr     string `json:"sink_expr"`
	InHandler    bool   `json:"in_admission_handler"`
	IdentityRef  bool   `json:"function_references_userinfo"`
	FromRequest  bool   `json:"source_from_admission_request"`
}

var fset = token.NewFileSet()
var root string

func src(n ast.Node) string {
	var b bytes.Buffer
	printer.Fprint(&b, fset, n)
	s := strings.Join(strings.Fields(b.String()), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
func loc(n ast.Node) string {
	p := fset.Position(n.Pos())
	r, _ := filepath.Rel(root, p.Filename)
	return fmt.Sprintf("%s:%d", r, p.Line)
}

// ---- per-function analysis ----
type fn struct {
	name    string
	body    *ast.BlockStmt
	handler bool
	types   map[string]string // var -> kind (best effort)
	decoded map[string]bool   // vars decoded from the admission request (requester-controlled)
}

type source struct {
	node       ast.Expr
	mtype, key string
	kind       string
	fromReq    bool
}

func kindOf(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return kindOf(t.X)
	case *ast.UnaryExpr:
		return kindOf(t.X)
	case *ast.CompositeLit:
		return kindOf(t.Type)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch t := e.(type) {
		case *ast.Ident:
			return t
		case *ast.SelectorExpr:
			e = t.X
		case *ast.IndexExpr:
			e = t.X
		case *ast.CallExpr:
			e = t.Fun
		case *ast.StarExpr:
			e = t.X
		case *ast.ParenExpr:
			e = t.X
		default:
			return nil
		}
	}
}

func collectTypes(f *fn, params *ast.FieldList) {
	if params != nil {
		for _, p := range params.List {
			for _, n := range p.Names {
				f.types[n.Name] = kindOf(p.Type)
			}
		}
	}
	ast.Inspect(f.body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == len(s.Rhs) {
				for i, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						if k := kindOf(s.Rhs[i]); k != "" {
							if _, isLit := s.Rhs[i].(*ast.CompositeLit); isLit {
								f.types[id.Name] = k
							} else if u, ok := s.Rhs[i].(*ast.UnaryExpr); ok && u.Op == token.AND {
								f.types[id.Name] = k
							}
						}
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := s.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Decode" || sel.Sel.Name == "DecodeRaw") && len(s.Args) == 2 {
				if r := rootIdent(s.Args[1]); r != nil {
					f.decoded[r.Name] = true
				}
			}
		case *ast.ValueSpec:
			if s.Type != nil {
				for _, n := range s.Names {
					f.types[n.Name] = kindOf(s.Type)
				}
			}
		case *ast.RangeStmt:
			// for _, ns := range nsList.Items  -> element kind unknown; approximate List->Kind
			if v, ok := s.Value.(*ast.Ident); ok {
				if r := rootIdent(s.X); r != nil {
					k := strings.TrimSuffix(f.types[r.Name], "List")
					if k != "" {
						f.types[v.Name] = k
					}
				}
			}
		}
		return true
	})
}

func findSources(f *fn) []source {
	var out []source
	ast.Inspect(f.body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false // analysed separately
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			mt, ok := metaFields[e.Sel.Name]
			if !ok {
				return true
			}
			r := rootIdent(e.X)
			k := ""
			if r != nil {
				k = f.types[r.Name]
			}
			out = append(out, source{node: e, mtype: mt, kind: k, fromReq: r != nil && f.decoded[r.Name]})
		case *ast.CallExpr:
			if s, ok := e.Fun.(*ast.SelectorExpr); ok {
				if mt, ok := metaGetters[s.Sel.Name]; ok && len(e.Args) == 0 {
					r := rootIdent(s.X)
					k := ""
					if r != nil {
						k = f.types[r.Name]
					}
					out = append(out, source{node: e, mtype: mt, kind: k, fromReq: r != nil && f.decoded[r.Name]})
				}
			}
		}
		return true
	})
	return out
}

// contains reports whether n contains target node or any ident in tainted.
func touches(n ast.Node, srcNode ast.Node, tainted map[string]bool) bool {
	hit := false
	ast.Inspect(n, func(x ast.Node) bool {
		if hit {
			return false
		}
		if x == srcNode {
			hit = true
			return false
		}
		if id, ok := x.(*ast.Ident); ok && tainted[id.Name] {
			hit = true
		}
		return true
	})
	return hit
}

func mtypeOf(kind string) string {
	switch {
	case kind == "Namespace":
		return "M1-A"
	case workloadKinds[kind]:
		return "M1-B"
	}
	return "M1-?"
}

func refsUserInfo(n ast.Node) bool {
	hit := false
	ast.Inspect(n, func(x ast.Node) bool {
		if s, ok := x.(*ast.SelectorExpr); ok && s.Sel.Name == "UserInfo" {
			hit = true
		}
		return !hit
	})
	return hit
}

// isAllowReturn: `return nil` (capsule convention) or a return containing admission.Allowed
func isAllowReturn(s ast.Stmt) bool {
	r, ok := s.(*ast.ReturnStmt)
	if !ok {
		return false
	}
	if len(r.Results) == 1 {
		if id, ok := r.Results[0].(*ast.Ident); ok && id.Name == "nil" {
			return true
		}
	}
	return strings.Contains(src(r), "Allowed(")
}

func isDenyBody(b *ast.BlockStmt) bool {
	t := src(b)
	return strings.Contains(t, "Denied(") || strings.Contains(t, "Errored(") || strings.Contains(t, "Forbidden")
}

// presence test: `_, ok := m[k]; ok`, `len(x) > 0`, `len(x) != 0`, `x != nil`
// absence test:  `!ok`, `len(x) == 0`, `x == nil`
func condPolarity(ifs *ast.IfStmt) string {
	c := src(ifs.Cond)
	switch {
	case strings.Contains(c, "== 0") || strings.HasPrefix(c, "!") || strings.Contains(c, "== nil"):
		return "absence"
	case strings.Contains(c, "> 0") || strings.Contains(c, "!= 0") || strings.Contains(c, "!= nil") || c == "ok" || strings.HasSuffix(c, "; ok"):
		return "presence"
	}
	if ifs.Init != nil && strings.Contains(src(ifs.Init), ", ok :=") && strings.TrimSpace(c) == "ok" {
		return "presence"
	}
	return ""
}

func analyse(f *fn, cands *[]Candidate) {
	srcs := findSources(f)
	userRef := refsUserInfo(f.body)
	for _, s := range srcs {
		if ix, ok := parentIndex(f.body, s.node); ok {
			s.key = src(ix.Index)
		}
		// propagate taint through assignments (flow-insensitive fixpoint)
		tainted := map[string]bool{}
		for changed := true; changed; {
			changed = false
			ast.Inspect(f.body, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				a, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				rhsHit := false
				for _, r := range a.Rhs {
					if touches(r, s.node, tainted) {
						rhsHit = true
					}
				}
				if rhsHit {
					for _, l := range a.Lhs {
						if id, ok := l.(*ast.Ident); ok && id.Name != "_" && !tainted[id.Name] {
							tainted[id.Name] = true
							changed = true
						}
					}
				}
				return true
			})
		}
		base := Candidate{MType: mtypeOf(s.kind), MetadataType: s.mtype, MetadataKey: s.key, ResourceType: s.kind,
			SourceLoc: loc(s.node), SourceExpr: src(s.node), Function: f.name, FromRequest: s.fromReq, InHandler: f.handler, IdentityRef: userRef}

		// sinks
		var walkBlock func(b *ast.BlockStmt)
		walkBlock = func(b *ast.BlockStmt) {
			for i, st := range b.List {
				ast.Inspect(st, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncLit:
						return false
					case *ast.BlockStmt:
						if x != b {
							walkBlock(x)
							return false
						}
					case *ast.IfStmt:
						if !(touches(x.Cond, s.node, tainted) || (x.Init != nil && touches(x.Init, s.node, tainted))) {
							return true
						}
						if !f.handler || isErrCheck(x.Cond) || x.End() < s.node.Pos() {
							return true
						}
						direct := s.fromReq && (within(x.Cond, s.node) || (x.Init != nil && within(x.Init, s.node)))
						c := base
						c.SinkLoc, c.SinkExpr = loc(x), "if "+src(x.Cond)
						pol := condPolarity(x)
						rest := b.List[i+1:]
						restAllows := len(rest) > 0 && isAllowReturn(rest[len(rest)-1])
						restIdentity := false
						for _, r := range rest {
							if refsUserInfo(r) {
								restIdentity = true
							}
						}
						switch {
						case direct && pol == "presence" && x.Else == nil && isDenyBody(x.Body) && restAllows && !restIdentity:
							c.MType, c.Pattern, c.Score = "M2", "presence-gated guard: metadata absent -> falls through to allow, no identity check", 6
						case direct && pol == "absence" && len(x.Body.List) == 1 && isAllowReturn(x.Body.List[0]):
							c.MType, c.Pattern, c.Score = "M2", "absence early-allow: metadata absent -> return allow before any identity check", 6
							if refsUserInfo(b) {
								c.Score = 4 // identity checked later in the same block on other path
							}
						default:
							c.MType, c.Pattern, c.Score = "M2", "metadata-dependent admission decision", 2
						}
						*cands = append(*cands, c)
					case *ast.CallExpr:
						sel, ok := x.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						argHit := false
						for _, a := range x.Args {
							if touches(a, s.node, tainted) {
								argHit = true
							}
						}
						if !argHit || x.End() < s.node.Pos() {
							return true
						}
						switch sel.Sel.Name {
						case "Get", "List":
							c := base
							c.SinkLoc, c.SinkExpr, c.Pattern, c.Score = loc(x), src(x), "metadata selects resource (lookup key/selector)", 3
							*cands = append(*cands, c)
						case "Create", "Update", "Patch", "Delete", "Allocate":
							c := base
							c.SinkLoc, c.SinkExpr, c.Pattern, c.Score = loc(x), src(x), "metadata reaches mutation", 3
							*cands = append(*cands, c)
						}
					}
					return true
				})
			}
		}
		walkBlock(f.body)
	}
}

func parentIndex(body ast.Node, target ast.Node) (*ast.IndexExpr, bool) {
	var res *ast.IndexExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if ix, ok := n.(*ast.IndexExpr); ok && ix.X == target {
			res = ix
			return false
		}
		return res == nil
	})
	return res, res != nil
}

func within(n ast.Node, t ast.Node) bool { return t.Pos() >= n.Pos() && t.End() <= n.End() }

func isErrCheck(c ast.Expr) bool {
	t := src(c)
	return t == "err != nil" || t == "err == nil"
}

func isHandlerType(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil {
		return false
	}
	for _, r := range ft.Results.List {
		if strings.Contains(src(r.Type), "admission.Response") {
			return true
		}
	}
	return false
}

func main() {
	root = os.Args[1]
	var cands []Candidate
	nSrc := 0
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			b := info.Name()
			if b == "vendor" || b == "e2e" || b == "test" || b == "hack" || strings.HasPrefix(b, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.Contains(p, "zz_generated") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var f *fn
			switch d := n.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					return true
				}
				name := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) > 0 {
					name = kindOf(d.Recv.List[0].Type) + "." + name
				}
				f = &fn{name: name, body: d.Body, handler: isHandlerType(d.Type), types: map[string]string{}, decoded: map[string]bool{}}
				collectTypes(f, d.Type.Params)
			case *ast.FuncLit:
				f = &fn{name: "func@" + loc(d), body: d.Body, handler: isHandlerType(d.Type), types: map[string]string{}, decoded: map[string]bool{}}
				collectTypes(f, d.Type.Params)
			}
			if f != nil {
				nSrc += len(findSources(f))
				analyse(f, &cands)
			}
			return true
		})
		return nil
	})
	seen := map[string]bool{}
	var dedup []Candidate
	for _, c := range cands {
		k := c.SinkLoc + "|" + c.Pattern + "|" + c.MetadataType
		if !seen[k] {
			seen[k] = true
			dedup = append(dedup, c)
		}
	}
	cands = dedup
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].Score != cands[j].Score {
			return cands[i].Score > cands[j].Score
		}
		return cands[i].SinkLoc < cands[j].SinkLoc
	})
	fmt.Fprintf(os.Stderr, "metadata_sources=%d candidates=%d\n", nSrc, len(cands))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(cands)
}
