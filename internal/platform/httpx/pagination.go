package httpx

import (
	"math"
	"net/http"
	"strconv"
)

// PaginationParams holds parsed offset-pagination parameters.
type PaginationParams struct {
	Page     int
	PageSize int
}

// ParsePagination reads page and page_size query params with defaults.
func ParsePagination(r *http.Request) PaginationParams {
	page := intQuery(r, "page", 1)
	pageSize := intQuery(r, "page_size", 20)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return PaginationParams{Page: page, PageSize: pageSize}
}

func intQuery(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

// PaginationMeta is the pagination metadata returned in list responses.
type PaginationMeta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// NewPaginationMeta builds the pagination metadata.
func NewPaginationMeta(p PaginationParams, total int64) PaginationMeta {
	tp := int(math.Ceil(float64(total) / float64(p.PageSize)))
	if tp < 1 {
		tp = 1
	}
	return PaginationMeta{
		Page:       p.Page,
		PageSize:   p.PageSize,
		Total:      total,
		TotalPages: tp,
	}
}

// ListResponse is a generic paginated list response.
type ListResponse[T any] struct {
	Data       []T            `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

// DataResponse is a single-resource response wrapper.
type DataResponse[T any] struct {
	Data T `json:"data"`
}

