package httpapi_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	fields := map[string]string{
		"name": `"valid"`, "description": `"text"`, "severity": `"low"`, "file_type": `"pdf"`, "first_seen_at": `"2099-01-01T00:00:00Z"`,
	}
	cases := []string{"", `null`, `[]`, `"text"`, `true`, `{`, `{}`, `{"name":"x"} {}`, `{"name":"x"} garbage`, `{"name":"x",}`, `{"Name":"x"}`, `{"name":"x","NAME":"y"}`, `{"name":"x","name":"y"}`, `{"name":"x","na\u006de":"y"}`, `{"name":"x","extra":"y"}`, `{"name":"x","created_at":"2099-01-01T00:00:00Z"}`, `{"name":"x","updated_at":"2099-01-01T00:00:00Z"}`}
	for _, key := range []string{"name", "description", "severity", "file_type", "first_seen_at"} {
		for _, bad := range []string{`null`, `1`, `true`, `[]`, `{}`} {
			parts := []string{}
			if key != "name" {
				parts = append(parts, `"name":"x"`)
			}
			parts = append(parts, fmt.Sprintf("%q:%s", key, bad))
			cases = append(cases, "{"+strings.Join(parts, ",")+"}")
		}
	}
	for _, value := range []string{`""`, `"2026-01-01"`, `"2026-01-01T00:00:00"`, `"2026-01-01T00:00:00+24:00"`, `"2026-01-01T00:00:00+03:60"`, `"2026-01-01T00:00:00,123Z"`, `"2026-02-30T00:00:00Z"`, `"0000-01-01T00:00:00Z"`} {
		cases = append(cases, `{"name":"x","first_seen_at":`+value+`}`)
	}
	cases = append(cases, `{"name":"\u0000"}`, `{"name":" \t\u2003"}`, `{"name":"x","description":"\u0000"}`, `{"name":"x","severity":""}`, `{"name":"x","severity":"HIGH"}`, `{"name":"x","file_type":""}`, `{"name":"x","file_type":"PE"}`, "{\"name\":\""+string([]byte{0xff})+"\"}")
	for _, key := range []string{"name", "description", "file_type"} {
		limit := map[string]int{"name": 256, "description": 4097, "file_type": 33}[key]
		parts := `"name":"x",`
		if key == "name" {
			parts = ""
		}
		cases = append(cases, "{"+parts+fmt.Sprintf("%q:%q", key, strings.Repeat("я", limit))+"}")
	}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			router, repo := setup()
			res := request(router, "PUT", "/info/"+testMD5, body, "application/json")
			assertStatus(t, res, 400)
			if repo.calls != 0 {
				t.Fatal("bad JSON reached repository")
			}
		})
	}
	// All optional fields may be explicitly provided as strings; unknown records yield 404, not a decoding error.
	parts := []string{}
	for k, v := range fields {
		parts = append(parts, fmt.Sprintf("%q:%s", k, v))
	}
	router, _ := setup()
	assertStatus(t, request(router, "PUT", "/info/"+testMD5, "{"+strings.Join(parts, ",")+"}", "application/json"), 404)
}

func TestCreateRequiredFields(t *testing.T) {
	for _, body := range []string{`{}`, `{"name":"x"}`, `{"md5":"` + testMD5 + `"}`, `{"md5":null,"name":"x"}`, `{"md5":1,"name":"x"}`, `{"MD5":"` + testMD5 + `","name":"x"}`, `{"md5":"bad","name":"x"}`} {
		router, repo := setup()
		assertStatus(t, request(router, "POST", "/info", body, "application/json"), 400)
		if repo.calls != 0 {
			t.Fatal("invalid create reached repository")
		}
	}
	router, repo := setup()
	assertStatus(t, request(router, "PUT", "/info/"+testMD5, `{"name":"x","md5":"`+testMD5+`"}`, "application/json"), 400)
	if repo.calls != 0 {
		t.Fatal("PUT accepted MD5 in body")
	}
}

func TestContentTypeAndBodyBoundary(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "application/json; charset=latin1", `application/json; charset=""`, "application/json; broken", "application/json, text/plain"} {
		router, repo := setup()
		assertStatus(t, request(router, "POST", "/info", `{}`, contentType), 415)
		if repo.calls != 0 {
			t.Fatal("unsupported content type reached repository")
		}
	}
	router, _ := setup()
	req := httptest.NewRequest("POST", "/info", strings.NewReader(`{}`))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Type", "application/json")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	assertStatus(t, res, 415)
	minimal := `{"md5":"` + testMD5 + `","name":"x"}`
	exact := minimal + strings.Repeat(" ", 65536-len(minimal))
	router, _ = setup()
	assertStatus(t, request(router, "POST", "/info", exact, "application/json; charset=UTF-8"), 201)
	router, repo := setup()
	assertStatus(t, request(router, "POST", "/info", exact+" ", "application/json"), 413)
	if repo.calls != 0 {
		t.Fatal("oversize request reached repository")
	}
	// ContentLength may be unknown for streamed input; the read limit still applies.
	req = httptest.NewRequest("PUT", "/info/"+testMD5, strings.NewReader(exact+" "))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	router.ServeHTTP(res, req)
	assertStatus(t, res, 413)
}
