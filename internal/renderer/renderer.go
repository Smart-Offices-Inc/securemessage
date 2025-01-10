package renderer

import (
	"html/template"
	"io"
	"local/securemessages/pkg/utils"

	"github.com/labstack/echo/v4"
)

type TemplateRenderer struct {
	templates *template.Template
}

func NewTemplateRenderer(pattern string) *TemplateRenderer {
	funcMap := template.FuncMap{
		"truncate": utils.Truncate, // Register the truncate function
	}
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseGlob(pattern))
	return &TemplateRenderer{templates: tmpl}
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}
