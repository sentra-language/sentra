package dataframe

import (
	"fmt"
	"math"
	"sort"
)

// Series represents a Pandas-like Series (1D labeled array)
type Series struct {
	Data  []interface{}
	Index []interface{}
	Name  string
	Dtype string
}

// NewSeries creates a new Series
func NewSeries(data []interface{}, name string) *Series {
	index := make([]interface{}, len(data))
	for i := range index {
		index[i] = i
	}

	return &Series{
		Data:  data,
		Index: index,
		Name:  name,
		Dtype: inferDtype(data),
	}
}

// NewSeriesWithIndex creates a new Series with custom index
func NewSeriesWithIndex(data []interface{}, index []interface{}, name string) *Series {
	if len(data) != len(index) {
		panic("data and index must have the same length")
	}

	return &Series{
		Data:  data,
		Index: index,
		Name:  name,
		Dtype: inferDtype(data),
	}
}

// inferDtype infers the data type from the data
func inferDtype(data []interface{}) string {
	if len(data) == 0 {
		return "object"
	}

	switch data[0].(type) {
	case float64, float32:
		return "float64"
	case int, int8, int16, int32, int64:
		return "int64"
	case bool:
		return "bool"
	case string:
		return "string"
	default:
		return "object"
	}
}

// Len returns the length of the series
func (s *Series) Len() int {
	return len(s.Data)
}

// Get returns the value at the given index
func (s *Series) Get(index interface{}) interface{} {
	for i, idx := range s.Index {
		if idx == index {
			return s.Data[i]
		}
	}
	return nil
}

// GetByPosition returns the value at the given position
func (s *Series) GetByPosition(pos int) interface{} {
	if pos < 0 || pos >= len(s.Data) {
		return nil
	}
	return s.Data[pos]
}

// Set sets the value at the given index
func (s *Series) Set(index interface{}, value interface{}) {
	for i, idx := range s.Index {
		if idx == index {
			s.Data[i] = value
			return
		}
	}
}

// Head returns the first n elements
func (s *Series) Head(n int) *Series {
	if n > len(s.Data) {
		n = len(s.Data)
	}

	return &Series{
		Data:  s.Data[:n],
		Index: s.Index[:n],
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// Tail returns the last n elements
func (s *Series) Tail(n int) *Series {
	if n > len(s.Data) {
		n = len(s.Data)
	}

	start := len(s.Data) - n
	return &Series{
		Data:  s.Data[start:],
		Index: s.Index[start:],
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// Sum returns the sum of numeric values
func (s *Series) Sum() float64 {
	sum := 0.0
	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			sum += num
		}
	}
	return sum
}

// Mean returns the mean of numeric values
func (s *Series) Mean() float64 {
	count := 0
	sum := 0.0

	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			sum += num
			count++
		}
	}

	if count == 0 {
		return math.NaN()
	}

	return sum / float64(count)
}

// Median returns the median of numeric values
func (s *Series) Median() float64 {
	var nums []float64
	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			nums = append(nums, num)
		}
	}

	if len(nums) == 0 {
		return math.NaN()
	}

	sort.Float64s(nums)
	n := len(nums)

	if n%2 == 0 {
		return (nums[n/2-1] + nums[n/2]) / 2.0
	}

	return nums[n/2]
}

// Std returns the standard deviation
func (s *Series) Std() float64 {
	var nums []float64
	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			nums = append(nums, num)
		}
	}

	if len(nums) == 0 {
		return math.NaN()
	}

	mean := 0.0
	for _, num := range nums {
		mean += num
	}
	mean /= float64(len(nums))

	variance := 0.0
	for _, num := range nums {
		diff := num - mean
		variance += diff * diff
	}
	variance /= float64(len(nums))

	return math.Sqrt(variance)
}

// Min returns the minimum value
func (s *Series) Min() float64 {
	min := math.Inf(1)
	found := false

	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			if num < min {
				min = num
				found = true
			}
		}
	}

	if !found {
		return math.NaN()
	}

	return min
}

// Max returns the maximum value
func (s *Series) Max() float64 {
	max := math.Inf(-1)
	found := false

	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			if num > max {
				max = num
				found = true
			}
		}
	}

	if !found {
		return math.NaN()
	}

	return max
}

// ValueCounts returns a map of value frequencies
func (s *Series) ValueCounts() map[interface{}]int {
	counts := make(map[interface{}]int)

	for _, val := range s.Data {
		counts[val]++
	}

	return counts
}

// Unique returns unique values
func (s *Series) Unique() []interface{} {
	seen := make(map[interface{}]bool)
	unique := make([]interface{}, 0)

	for _, val := range s.Data {
		key := fmt.Sprintf("%v", val)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, val)
		}
	}

	return unique
}

// Filter filters the series based on a condition
func (s *Series) Filter(condition func(interface{}) bool) *Series {
	data := make([]interface{}, 0)
	index := make([]interface{}, 0)

	for i, val := range s.Data {
		if condition(val) {
			data = append(data, val)
			index = append(index, s.Index[i])
		}
	}

	return &Series{
		Data:  data,
		Index: index,
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// Map applies a function to each element
func (s *Series) Map(fn func(interface{}) interface{}) *Series {
	data := make([]interface{}, len(s.Data))

	for i, val := range s.Data {
		data[i] = fn(val)
	}

	return &Series{
		Data:  data,
		Index: s.Index,
		Name:  s.Name,
		Dtype: inferDtype(data),
	}
}

// Sort sorts the series
func (s *Series) Sort(ascending bool) *Series {
	type pair struct {
		data  interface{}
		index interface{}
	}

	pairs := make([]pair, len(s.Data))
	for i := range s.Data {
		pairs[i] = pair{s.Data[i], s.Index[i]}
	}

	sort.Slice(pairs, func(i, j int) bool {
		vi, voki := toFloat64(pairs[i].data)
		vj, vokj := toFloat64(pairs[j].data)

		if voki && vokj {
			if ascending {
				return vi < vj
			}
			return vi > vj
		}

		// Fallback to string comparison
		si := fmt.Sprintf("%v", pairs[i].data)
		sj := fmt.Sprintf("%v", pairs[j].data)

		if ascending {
			return si < sj
		}
		return si > sj
	})

	data := make([]interface{}, len(pairs))
	index := make([]interface{}, len(pairs))

	for i, p := range pairs {
		data[i] = p.data
		index[i] = p.index
	}

	return &Series{
		Data:  data,
		Index: index,
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// IsNull returns a boolean series indicating null values
func (s *Series) IsNull() []bool {
	result := make([]bool, len(s.Data))
	for i, val := range s.Data {
		result[i] = (val == nil)
	}
	return result
}

// FillNA fills null values with a given value
func (s *Series) FillNA(value interface{}) *Series {
	data := make([]interface{}, len(s.Data))

	for i, val := range s.Data {
		if val == nil {
			data[i] = value
		} else {
			data[i] = val
		}
	}

	return &Series{
		Data:  data,
		Index: s.Index,
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// Copy creates a deep copy
func (s *Series) Copy() *Series {
	dataCopy := make([]interface{}, len(s.Data))
	indexCopy := make([]interface{}, len(s.Index))

	copy(dataCopy, s.Data)
	copy(indexCopy, s.Index)

	return &Series{
		Data:  dataCopy,
		Index: indexCopy,
		Name:  s.Name,
		Dtype: s.Dtype,
	}
}

// ToFloat64Array converts series to float64 array
func (s *Series) ToFloat64Array() []float64 {
	result := make([]float64, 0, len(s.Data))

	for _, val := range s.Data {
		if num, ok := toFloat64(val); ok {
			result = append(result, num)
		}
	}

	return result
}

// ToStringArray converts series to string array
func (s *Series) ToStringArray() []string {
	result := make([]string, len(s.Data))

	for i, val := range s.Data {
		result[i] = fmt.Sprintf("%v", val)
	}

	return result
}

// ToMap converts series to map representation
func (s *Series) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"data":  s.Data,
		"index": s.Index,
		"name":  s.Name,
		"dtype": s.Dtype,
		"size":  len(s.Data),
	}
}

// toFloat64 converts an interface{} to float64
func toFloat64(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}
