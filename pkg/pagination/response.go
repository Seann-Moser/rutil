package pagination

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Seann-Moser/cutil/logc"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/h2non/bimg"
	"go.uber.org/zap"
)

type Response struct {
	showError bool
}

type BaseResponseGeneric[T any] struct {
	Message string      `json:"message"`
	Data    T           `json:"data,omitempty"`
	Page    *Pagination `json:"page,omitempty"`
}

type BaseResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Page    *Pagination `json:"page,omitempty"`
}

func NewResponse(showErr bool) *Response {
	return &Response{showError: showErr}
}

func (resp *Response) Error(ctx context.Context, w http.ResponseWriter, err error, code int, message string) {
	w.WriteHeader(code)
	if err != nil {
		logc.Error(ctx, message, zap.Error(err), zap.Int("code", code))
	}
	var dataErr error
	if err != nil && resp.showError {
		dataErr = err
	}
	EncodeErr := json.NewEncoder(w).Encode(BaseResponse{
		Message: message,
		Data:    dataErr,
	})
	if EncodeErr != nil {
		logc.Warn(ctx, "failed encoding response", zap.Error(EncodeErr))
	}
}

func (resp *Response) PaginationResponse(ctx context.Context, w http.ResponseWriter, data interface{}, page *Pagination) {
	d, err := json.Marshal(data)
	if err != nil {
		logc.Error(ctx, "failed to marshall data", zap.Error(err))
		return
	}
	var pageData []interface{}
	err = json.Unmarshal(d, &pageData)
	if err != nil {
		logc.Error(ctx, "failed to encode to []interface", zap.Error(err))
		return
	}
	w.WriteHeader(http.StatusOK)
	bytes, err := json.MarshalIndent(BaseResponse{
		Data: getRange(pageData, page),
		Page: page,
	}, "", "    ")
	if err != nil {
		logc.Error(ctx, "failed to encode response")
	}
	_, EncodeErr := w.Write(bytes)
	if EncodeErr != nil {
		logc.Warn(ctx, "failed encoding response", zap.Error(EncodeErr))
	}
}

func getRange(data []interface{}, page *Pagination) []interface{} {
	page.TotalItems = uint(len(data))
	if page.ItemsPerPage == 0 {
		page.ItemsPerPage = MaxItemsPerPage
	}
	if page.ItemsPerPage <= 0 {
		page.ItemsPerPage = 1
	}
	if page.CurrentPage <= 0 {
		page.CurrentPage = 1
	}
	if page.TotalItems < page.ItemsPerPage {
		page.TotalPages = 1
	} else {
		page.TotalPages = uint(math.Ceil(float64(page.TotalItems) / float64(page.ItemsPerPage)))
	}
	page.NextPage = page.CurrentPage + 1
	if page.NextPage > page.TotalPages {
		page.NextPage = page.TotalPages
	}
	if page.CurrentPage > page.TotalPages {
		page.CurrentPage = page.TotalPages
	}
	if len(data) < int(page.ItemsPerPage) {
		return data
	}
	min := int((page.CurrentPage - 1) * page.ItemsPerPage)
	if min < 0 {
		min = 0
	}
	max := min + int(page.ItemsPerPage)
	if min > len(data) {
		return []interface{}{}
	}
	if max > len(data) {
		return data[min:]
	}
	return data[min:max]
}

func (resp *Response) Message(ctx context.Context, w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusOK)
	bytes, err := json.MarshalIndent(BaseResponse{
		Message: msg,
	}, "", "    ")
	if err != nil {
		logc.Error(ctx, "failed to encode response")
	}
	_, EncodeErr := w.Write(bytes)
	if EncodeErr != nil {
		logc.Error(ctx, "failed encoding response", zap.Error(EncodeErr))
	}
}

func (resp *Response) Raw(ctx context.Context, w http.ResponseWriter, r *http.Response) {
	w.WriteHeader(r.StatusCode)
	if r.Body != nil {
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			logc.Error(ctx, "failed reading body", zap.Error(err))
			return
		}
		for k, v := range r.Header {
			w.Header().Set(k, v[0])
		}
		_, err = w.Write(b)
		if err != nil {
			logc.Error(ctx, "failed encoding response", zap.Error(err))
			return
		}
	}
}

func (resp *Response) DataResponse(ctx context.Context, w http.ResponseWriter, data interface{}, code int) {
	w.WriteHeader(code)
	bytes, err := json.MarshalIndent(BaseResponse{
		Data: data,
	}, "", "    ")
	if err != nil {
		logc.Error(ctx, "failed to encode response")
	}
	_, EncodeErr := w.Write(bytes)
	if EncodeErr != nil {
		logc.Error(ctx, "failed encoding response", zap.Error(EncodeErr))
	}
}

func (resp *Response) File(w http.ResponseWriter, file string, download bool) (int64, error) {
	if info, err := os.Stat(file); err != nil || info.IsDir() {
		return 0, err
	}
	filename := strings.Split(file, "/")
	w.Header().Set("filename", filename[len(filename)-1])
	if download {
		w.Header().Set("Content-Description", "File Transfer")
		w.Header().Set("Content-Transfer-Encoding", "binary")
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(filename[len(filename)-1]))
		//w.Header().Set("Content-Type", "application/octet-stream")
	}
	f, _ := os.Open(file)
	defer func() {
		_ = f.Close()
	}()

	fileHeader := make([]byte, 512)
	_, err := f.Read(fileHeader)
	if err != nil {
		return 0, err
	}
	fileStat, _ := f.Stat()
	w.Header().Set("Content-Type", http.DetectContentType(fileHeader))
	w.Header().Set("Content-Length", strconv.FormatInt(fileStat.Size(), 10))
	_, err = f.Seek(0, 0)
	if err != nil {
		return 0, err
	}
	return io.Copy(w, f)
}

func CompressImage(file string, compressRatio float64) error {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", file)
	}
	// Step 3: Read the image file into memory
	imageBuffer, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Step 4: Use bimg to compress the image
	options := bimg.Options{
		Quality: int(compressRatio * 100), // compressRatio should be between 0 and 1
	}
	newImage, err := bimg.NewImage(imageBuffer).Process(options)
	if err != nil {
		return fmt.Errorf("failed to process image: %v", err)
	}

	// Step 5: Save the compressed image back to disk
	err = os.WriteFile(file, newImage, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}
