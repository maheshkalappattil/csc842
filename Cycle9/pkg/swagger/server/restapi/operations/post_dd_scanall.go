// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// PostDdScanallHandlerFunc turns a function with the right signature into a post dd scanall handler
type PostDdScanallHandlerFunc func(PostDdScanallParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostDdScanallHandlerFunc) Handle(params PostDdScanallParams) middleware.Responder {
	return fn(params)
}

// PostDdScanallHandler interface for that can handle valid post dd scanall params
type PostDdScanallHandler interface {
	Handle(PostDdScanallParams) middleware.Responder
}

// NewPostDdScanall creates a new http.Handler for the post dd scanall operation
func NewPostDdScanall(ctx *middleware.Context, handler PostDdScanallHandler) *PostDdScanall {
	return &PostDdScanall{Context: ctx, Handler: handler}
}

/*
	PostDdScanall swagger:route POST /dd/scanall postDdScanall

scans all unread mails!
*/
type PostDdScanall struct {
	Context *middleware.Context
	Handler PostDdScanallHandler
}

func (o *PostDdScanall) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewPostDdScanallParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}