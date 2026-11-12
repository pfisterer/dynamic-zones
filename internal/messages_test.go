package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The texts for people are pairs, German and English (golib msg). These constructors take the German text and then the English one, as their first two arguments.
var pairConstructors = map[string]int{
	"msg.T":      0,
	"msg.F":      0,
	"msg.Errorf": 0,
	"invalid":    0,
}

// germanAllowed are German literals outside a pair that are deliberately not answered in English. Empty today: list a text here only with the reason it never reaches a REST or MCP response in the caller's language (stored data, a log line the scan does not recognise as one).
var germanAllowed = []string{}

var (
	verb = regexp.MustCompile(`%(\[\d+\])?[-+# 0]*\d*(\.\d+)?[a-zA-Z]`)
	// looksGerman is a German text: an umlaut or ß, or one of the words the German sentences here have one of.
	looksGerman = regexp.MustCompile(`[äöüÄÖÜß]|\b(nicht|ist|darf|muss|kein|keine|sind|lässt|wird|werden|oder|und|der|die|das|dem|den|ein|eine|einem|einen|für|mit|nur|bereits|zu|von|sich|gibt|fehlt|erforderlich|erlaubt|Anmeldung|Anfrage|Fehler|Methode|Zonen|Regel|Regeln|Laufzeit|Jetzt|[Uu]ngültig\w*)\b`)
	// letters is any letter: a pair without one outside its format verbs ("%s: %s") is the same in both languages by design.
	letters = regexp.MustCompile(`[A-Za-zÄÖÜäöüß]`)
)

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
	}
	return ""
}

// stringLit is the value of a string literal; false for anything else.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func verbs(s string) []string {
	v := verb.FindAllString(strings.ReplaceAll(s, "%%", ""), -1)
	slices.Sort(v)
	return v
}

// isLogCall reports a call of the logger (zap's Infof, Warnw, Errorf, Debug, Fatalf …): its texts are for operators and stay as they are.
func isLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	for _, p := range []string{"Info", "Warn", "Error", "Debug", "Fatal", "Panic"} {
		if strings.HasPrefix(sel.Sel.Name, p) {
			return true
		}
	}
	return false
}

// Every text for people the service can answer with (REST and MCP) has its English twin: every pair names both languages, with the same format verbs, and no German literal reaches people outside a pair. Log messages, struct tags (the API documentation and the MCP schemas) and the tests are not looked at; what a test pins is the text of each language.
func TestMessagesForPeopleHaveAnEnglishTwin(t *testing.T) {
	fset := token.NewFileSet()
	pairs := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "generated_docs" || d.Name() == "test_helpers") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		skip := map[*ast.BasicLit]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Field:
				if n.Tag != nil {
					skip[n.Tag] = true
				}
				return true
			case *ast.CallExpr:
				if isLogCall(n) {
					for _, a := range n.Args {
						if lit, ok := a.(*ast.BasicLit); ok {
							skip[lit] = true
						}
					}
				}
				i, ok := pairConstructors[calleeName(n)]
				if !ok || len(n.Args) < i+2 {
					return true
				}
				de, okDE := stringLit(n.Args[i])
				en, okEN := stringLit(n.Args[i+1])
				if !okDE || !okEN {
					return true // a pair passed on (de, en parameters), checked where it is written
				}
				pairs++
				skip[n.Args[i].(*ast.BasicLit)], skip[n.Args[i+1].(*ast.BasicLit)] = true, true
				pos := fset.Position(n.Pos())
				switch {
				case de == "" || en == "":
					t.Errorf("%s: %s(%q, %q): a text for people needs German and English", pos, calleeName(n), de, en)
				case de == en && letters.MatchString(verb.ReplaceAllString(de, "")):
					t.Errorf("%s: %s(%q, …): the English text is the German one", pos, calleeName(n), de)
				case !slices.Equal(verbs(de), verbs(en)):
					t.Errorf("%s: %s: the format verbs differ: %v in %q, %v in %q", pos, calleeName(n), verbs(de), de, verbs(en), en)
				case looksGerman.MatchString(en):
					t.Errorf("%s: %s: the English text looks German: %q", pos, calleeName(n), en)
				}
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || skip[lit] {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || !looksGerman.MatchString(s) || slices.Contains(germanAllowed, s) || strings.HasPrefix(lit.Value, "`") && strings.Contains(s, "\n") {
				return true
			}
			t.Errorf("%s: %q looks like a German text for people outside a pair (msg.T, msg.F, msg.Errorf, invalid); give it its English twin, or list it in germanAllowed if it never reaches people", fset.Position(lit.Pos()), s)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d texts for people in German and English", pairs)
	if pairs < 150 {
		t.Fatalf("found only %d pairs; is the scan still looking at the right calls?", pairs)
	}
}
