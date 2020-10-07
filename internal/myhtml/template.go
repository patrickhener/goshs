package myhtml

const dispTmpl = `
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>Directory listing for {{.Path}}</title>
  </head>
  <body>
    <div>
    <h1>Upload File</h1>
    {{ if (eq .Path "/") }}
    <form id="upload" name="upload" enctype="multipart/form-data" autocomplete="off" action="/upload" method="POST">
    {{ else }}
    <form id="upload" name="upload" enctype="multipart/form-data" autocomplete="off" action="{{.Path}}/upload" method="POST">
    {{ end }}
    <input name="file" type="file" id="upload" />
    <input type="submit" value="upload">
    </form>
    </div>
    <hr />
    <div>
    <h1>Directory listing for {{.Path}}</h1>
    <hr />
	<ul>
	  {{range .Content}}
		<li><a href="/{{.URI}}">{{.Name}}</a></li>
	  {{ end }}
  </ul>
  </div>
    <hr />
  </body>
</html>
`

const notFoundTmpl = `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
`

const noAccessTmpl = `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 500</p>
        <p>Message: No permission to access the file.</p>
        <p>Error code explanation: HTTPStatus.PERMISSION_DENIED - You have no permission to access the file.</p>
    </body>
</html>
`

// GetTemplate will deliver the template depending on a 'name'
func GetTemplate(name string) string {
	switch name {
	case "display":
		return dispTmpl
	case "404":
		return notFoundTmpl
	case "500":
		return noAccessTmpl
	}
	return ""
}
