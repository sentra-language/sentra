// Package dataframe provides NumPy/Pandas-like data structures for Sentra
package dataframe

import (
	"fmt"
	"math"
	"sort"
)

// NDArray represents a NumPy-like N-dimensional array
type NDArray struct {
	Data   []float64
	Shape  []int
	Size   int
	Dtype  string // "float64", "int64", "bool"
}

// NewArray creates a new NDArray from a slice of values
func NewArray(data []float64) *NDArray {
	return &NDArray{
		Data:  data,
		Shape: []int{len(data)},
		Size:  len(data),
		Dtype: "float64",
	}
}

// NewArrayWithShape creates a new NDArray with specific shape
func NewArrayWithShape(data []float64, shape []int) *NDArray {
	size := 1
	for _, dim := range shape {
		size *= dim
	}

	if len(data) != size {
		panic(fmt.Sprintf("data length %d doesn't match shape size %d", len(data), size))
	}

	return &NDArray{
		Data:  data,
		Shape: shape,
		Size:  size,
		Dtype: "float64",
	}
}

// Zeros creates an array filled with zeros
func Zeros(shape ...int) *NDArray {
	size := 1
	for _, dim := range shape {
		size *= dim
	}

	data := make([]float64, size)
	return &NDArray{
		Data:  data,
		Shape: shape,
		Size:  size,
		Dtype: "float64",
	}
}

// Ones creates an array filled with ones
func Ones(shape ...int) *NDArray {
	size := 1
	for _, dim := range shape {
		size *= dim
	}

	data := make([]float64, size)
	for i := range data {
		data[i] = 1.0
	}

	return &NDArray{
		Data:  data,
		Shape: shape,
		Size:  size,
		Dtype: "float64",
	}
}

// Arange creates an array with evenly spaced values
func Arange(start, stop, step float64) *NDArray {
	if step == 0 {
		panic("step cannot be zero")
	}

	size := int(math.Ceil((stop - start) / step))
	data := make([]float64, size)

	for i := 0; i < size; i++ {
		data[i] = start + float64(i)*step
	}

	return NewArray(data)
}

// Linspace creates an array with linearly spaced values
func Linspace(start, stop float64, num int) *NDArray {
	if num <= 0 {
		panic("num must be positive")
	}

	data := make([]float64, num)
	if num == 1 {
		data[0] = start
		return NewArray(data)
	}

	step := (stop - start) / float64(num-1)
	for i := 0; i < num; i++ {
		data[i] = start + float64(i)*step
	}

	return NewArray(data)
}

// Reshape changes the shape of the array
func (arr *NDArray) Reshape(shape ...int) *NDArray {
	size := 1
	for _, dim := range shape {
		size *= dim
	}

	if size != arr.Size {
		panic(fmt.Sprintf("cannot reshape array of size %d into shape %v", arr.Size, shape))
	}

	return &NDArray{
		Data:  arr.Data,
		Shape: shape,
		Size:  size,
		Dtype: arr.Dtype,
	}
}

// Add performs element-wise addition
func (arr *NDArray) Add(other *NDArray) *NDArray {
	if arr.Size != other.Size {
		panic("arrays must have the same size")
	}

	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = arr.Data[i] + other.Data[i]
	}

	return NewArrayWithShape(result, arr.Shape)
}

// AddScalar adds a scalar to all elements
func (arr *NDArray) AddScalar(scalar float64) *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = arr.Data[i] + scalar
	}

	return NewArrayWithShape(result, arr.Shape)
}

// Subtract performs element-wise subtraction
func (arr *NDArray) Subtract(other *NDArray) *NDArray {
	if arr.Size != other.Size {
		panic("arrays must have the same size")
	}

	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = arr.Data[i] - other.Data[i]
	}

	return NewArrayWithShape(result, arr.Shape)
}

// Multiply performs element-wise multiplication
func (arr *NDArray) Multiply(other *NDArray) *NDArray {
	if arr.Size != other.Size {
		panic("arrays must have the same size")
	}

	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = arr.Data[i] * other.Data[i]
	}

	return NewArrayWithShape(result, arr.Shape)
}

// MultiplyScalar multiplies all elements by a scalar
func (arr *NDArray) MultiplyScalar(scalar float64) *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = arr.Data[i] * scalar
	}

	return NewArrayWithShape(result, arr.Shape)
}

// Divide performs element-wise division
func (arr *NDArray) Divide(other *NDArray) *NDArray {
	if arr.Size != other.Size {
		panic("arrays must have the same size")
	}

	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		if other.Data[i] == 0 {
			result[i] = math.NaN()
		} else {
			result[i] = arr.Data[i] / other.Data[i]
		}
	}

	return NewArrayWithShape(result, arr.Shape)
}

// Dot performs matrix multiplication (for 2D arrays)
func (arr *NDArray) Dot(other *NDArray) *NDArray {
	if len(arr.Shape) != 2 || len(other.Shape) != 2 {
		panic("dot product requires 2D arrays")
	}

	m, n := arr.Shape[0], arr.Shape[1]
	n2, p := other.Shape[0], other.Shape[1]

	if n != n2 {
		panic(fmt.Sprintf("incompatible shapes for dot product: (%d,%d) and (%d,%d)", m, n, n2, p))
	}

	result := make([]float64, m*p)

	for i := 0; i < m; i++ {
		for j := 0; j < p; j++ {
			sum := 0.0
			for k := 0; k < n; k++ {
				sum += arr.Data[i*n+k] * other.Data[k*p+j]
			}
			result[i*p+j] = sum
		}
	}

	return NewArrayWithShape(result, []int{m, p})
}

// Transpose transposes the array (for 2D arrays)
func (arr *NDArray) Transpose() *NDArray {
	if len(arr.Shape) != 2 {
		panic("transpose requires 2D array")
	}

	rows, cols := arr.Shape[0], arr.Shape[1]
	result := make([]float64, arr.Size)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			result[j*rows+i] = arr.Data[i*cols+j]
		}
	}

	return NewArrayWithShape(result, []int{cols, rows})
}

// Sum returns the sum of all elements
func (arr *NDArray) Sum() float64 {
	sum := 0.0
	for _, val := range arr.Data {
		sum += val
	}
	return sum
}

// Mean returns the mean of all elements
func (arr *NDArray) Mean() float64 {
	if arr.Size == 0 {
		return 0.0
	}
	return arr.Sum() / float64(arr.Size)
}

// Std returns the standard deviation
func (arr *NDArray) Std() float64 {
	if arr.Size == 0 {
		return 0.0
	}

	mean := arr.Mean()
	variance := 0.0

	for _, val := range arr.Data {
		diff := val - mean
		variance += diff * diff
	}

	variance /= float64(arr.Size)
	return math.Sqrt(variance)
}

// Var returns the variance
func (arr *NDArray) Var() float64 {
	if arr.Size == 0 {
		return 0.0
	}

	mean := arr.Mean()
	variance := 0.0

	for _, val := range arr.Data {
		diff := val - mean
		variance += diff * diff
	}

	return variance / float64(arr.Size)
}

// Min returns the minimum value
func (arr *NDArray) Min() float64 {
	if arr.Size == 0 {
		return math.NaN()
	}

	min := arr.Data[0]
	for _, val := range arr.Data[1:] {
		if val < min {
			min = val
		}
	}
	return min
}

// Max returns the maximum value
func (arr *NDArray) Max() float64 {
	if arr.Size == 0 {
		return math.NaN()
	}

	max := arr.Data[0]
	for _, val := range arr.Data[1:] {
		if val > max {
			max = val
		}
	}
	return max
}

// ArgMin returns the index of the minimum value
func (arr *NDArray) ArgMin() int {
	if arr.Size == 0 {
		return -1
	}

	minIdx := 0
	minVal := arr.Data[0]

	for i := 1; i < arr.Size; i++ {
		if arr.Data[i] < minVal {
			minVal = arr.Data[i]
			minIdx = i
		}
	}

	return minIdx
}

// ArgMax returns the index of the maximum value
func (arr *NDArray) ArgMax() int {
	if arr.Size == 0 {
		return -1
	}

	maxIdx := 0
	maxVal := arr.Data[0]

	for i := 1; i < arr.Size; i++ {
		if arr.Data[i] > maxVal {
			maxVal = arr.Data[i]
			maxIdx = i
		}
	}

	return maxIdx
}

// Sort sorts the array in place
func (arr *NDArray) Sort() {
	sort.Float64s(arr.Data)
}

// Copy creates a deep copy of the array
func (arr *NDArray) Copy() *NDArray {
	dataCopy := make([]float64, len(arr.Data))
	copy(dataCopy, arr.Data)

	shapeCopy := make([]int, len(arr.Shape))
	copy(shapeCopy, arr.Shape)

	return &NDArray{
		Data:  dataCopy,
		Shape: shapeCopy,
		Size:  arr.Size,
		Dtype: arr.Dtype,
	}
}

// Abs returns absolute values
func (arr *NDArray) Abs() *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = math.Abs(arr.Data[i])
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Sqrt returns square root of all elements
func (arr *NDArray) Sqrt() *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = math.Sqrt(arr.Data[i])
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Pow raises all elements to a power
func (arr *NDArray) Pow(exponent float64) *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = math.Pow(arr.Data[i], exponent)
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Exp returns e^x for all elements
func (arr *NDArray) Exp() *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = math.Exp(arr.Data[i])
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Log returns natural logarithm of all elements
func (arr *NDArray) Log() *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		result[i] = math.Log(arr.Data[i])
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Clip clips values to a range
func (arr *NDArray) Clip(min, max float64) *NDArray {
	result := make([]float64, arr.Size)
	for i := 0; i < arr.Size; i++ {
		val := arr.Data[i]
		if val < min {
			result[i] = min
		} else if val > max {
			result[i] = max
		} else {
			result[i] = val
		}
	}
	return NewArrayWithShape(result, arr.Shape)
}

// Cumsum returns cumulative sum
func (arr *NDArray) Cumsum() *NDArray {
	result := make([]float64, arr.Size)
	result[0] = arr.Data[0]

	for i := 1; i < arr.Size; i++ {
		result[i] = result[i-1] + arr.Data[i]
	}

	return NewArrayWithShape(result, arr.Shape)
}

// Percentile returns the value at a given percentile (0-100)
func (arr *NDArray) Percentile(p float64) float64 {
	if arr.Size == 0 {
		return math.NaN()
	}

	if p < 0 || p > 100 {
		panic("percentile must be between 0 and 100")
	}

	sorted := arr.Copy()
	sorted.Sort()

	index := (p / 100.0) * float64(arr.Size-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sorted.Data[lower]
	}

	// Linear interpolation
	weight := index - float64(lower)
	return sorted.Data[lower]*(1-weight) + sorted.Data[upper]*weight
}

// ToMap converts array to map representation
func (arr *NDArray) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"data":  arr.Data,
		"shape": arr.Shape,
		"size":  arr.Size,
		"dtype": arr.Dtype,
	}
}
