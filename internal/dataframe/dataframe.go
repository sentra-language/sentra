package dataframe

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// DataFrame represents a Pandas-like DataFrame
type DataFrame struct {
	Columns map[string]*Series
	Index   []interface{}
	NRows   int
	NCols   int
}

// NewDataFrame creates a new DataFrame from a map of columns
func NewDataFrame(data map[string][]interface{}) *DataFrame {
	if len(data) == 0 {
		return &DataFrame{
			Columns: make(map[string]*Series),
			Index:   make([]interface{}, 0),
			NRows:   0,
			NCols:   0,
		}
	}

	// Get number of rows from first column
	var nrows int
	for _, col := range data {
		nrows = len(col)
		break
	}

	// Validate all columns have the same length
	for colName, col := range data {
		if len(col) != nrows {
			panic(fmt.Sprintf("column %s has %d rows, expected %d", colName, len(col), nrows))
		}
	}

	// Create index
	index := make([]interface{}, nrows)
	for i := range index {
		index[i] = i
	}

	// Create series for each column
	columns := make(map[string]*Series)
	for colName, colData := range data {
		columns[colName] = NewSeriesWithIndex(colData, index, colName)
	}

	return &DataFrame{
		Columns: columns,
		Index:   index,
		NRows:   nrows,
		NCols:   len(data),
	}
}

// ReadCSV reads a CSV file into a DataFrame
func ReadCSV(filename string) (*DataFrame, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return NewDataFrame(make(map[string][]interface{})), nil
	}

	// First row is headers
	headers := records[0]
	data := make(map[string][]interface{})

	for _, header := range headers {
		data[header] = make([]interface{}, 0)
	}

	// Process data rows
	for _, record := range records[1:] {
		for i, value := range record {
			if i < len(headers) {
				data[headers[i]] = append(data[headers[i]], value)
			}
		}
	}

	return NewDataFrame(data), nil
}

// Select returns a new DataFrame with only the specified columns
func (df *DataFrame) Select(columns []string) *DataFrame {
	data := make(map[string][]interface{})

	for _, colName := range columns {
		if series, exists := df.Columns[colName]; exists {
			data[colName] = series.Data
		}
	}

	return NewDataFrame(data)
}

// Filter returns a new DataFrame with rows that match the condition
func (df *DataFrame) Filter(condition func(map[string]interface{}) bool) *DataFrame {
	data := make(map[string][]interface{})

	// Initialize columns
	for colName := range df.Columns {
		data[colName] = make([]interface{}, 0)
	}

	// Filter rows
	for i := 0; i < df.NRows; i++ {
		row := df.GetRow(i)
		if condition(row) {
			for colName, series := range df.Columns {
				data[colName] = append(data[colName], series.Data[i])
			}
		}
	}

	return NewDataFrame(data)
}

// GetRow returns a row as a map
func (df *DataFrame) GetRow(index int) map[string]interface{} {
	if index < 0 || index >= df.NRows {
		return nil
	}

	row := make(map[string]interface{})
	for colName, series := range df.Columns {
		row[colName] = series.Data[index]
	}

	return row
}

// Head returns the first n rows
func (df *DataFrame) Head(n int) *DataFrame {
	if n > df.NRows {
		n = df.NRows
	}

	data := make(map[string][]interface{})
	for colName, series := range df.Columns {
		data[colName] = series.Data[:n]
	}

	return NewDataFrame(data)
}

// Tail returns the last n rows
func (df *DataFrame) Tail(n int) *DataFrame {
	if n > df.NRows {
		n = df.NRows
	}

	start := df.NRows - n
	data := make(map[string][]interface{})

	for colName, series := range df.Columns {
		data[colName] = series.Data[start:]
	}

	return NewDataFrame(data)
}

// GroupBy groups the DataFrame by a column
func (df *DataFrame) GroupBy(column string) *GroupedDataFrame {
	series, exists := df.Columns[column]
	if !exists {
		panic(fmt.Sprintf("column %s not found", column))
	}

	groups := make(map[interface{}][]int)

	// Group row indices by column value
	for i, val := range series.Data {
		key := fmt.Sprintf("%v", val)
		groups[key] = append(groups[key], i)
	}

	return &GroupedDataFrame{
		DF:        df,
		GroupCol:  column,
		Groups:    groups,
	}
}

// Sort sorts the DataFrame by a column
func (df *DataFrame) Sort(column string, ascending bool) *DataFrame {
	series, exists := df.Columns[column]
	if !exists {
		panic(fmt.Sprintf("column %s not found", column))
	}

	// Create index array
	indices := make([]int, df.NRows)
	for i := range indices {
		indices[i] = i
	}

	// Sort indices based on column values
	sort.Slice(indices, func(i, j int) bool {
		vi, voki := toFloat64(series.Data[indices[i]])
		vj, vokj := toFloat64(series.Data[indices[j]])

		if voki && vokj {
			if ascending {
				return vi < vj
			}
			return vi > vj
		}

		// Fallback to string comparison
		si := fmt.Sprintf("%v", series.Data[indices[i]])
		sj := fmt.Sprintf("%v", series.Data[indices[j]])

		if ascending {
			return si < sj
		}
		return si > sj
	})

	// Create new DataFrame with sorted data
	data := make(map[string][]interface{})
	for colName, colSeries := range df.Columns {
		newCol := make([]interface{}, df.NRows)
		for i, idx := range indices {
			newCol[i] = colSeries.Data[idx]
		}
		data[colName] = newCol
	}

	return NewDataFrame(data)
}

// Join performs an inner join with another DataFrame
func (df *DataFrame) Join(other *DataFrame, on string) *DataFrame {
	// Check if join column exists in both DataFrames
	leftSeries, leftExists := df.Columns[on]
	rightSeries, rightExists := other.Columns[on]

	if !leftExists || !rightExists {
		panic(fmt.Sprintf("join column %s not found in both DataFrames", on))
	}

	// Create index maps for fast lookup
	rightIndex := make(map[string][]int)
	for i, val := range rightSeries.Data {
		key := fmt.Sprintf("%v", val)
		rightIndex[key] = append(rightIndex[key], i)
	}

	// Initialize result columns
	data := make(map[string][]interface{})
	for colName := range df.Columns {
		data[colName] = make([]interface{}, 0)
	}
	for colName := range other.Columns {
		if colName != on {
			data[colName] = make([]interface{}, 0)
		}
	}

	// Perform join
	for i, leftVal := range leftSeries.Data {
		key := fmt.Sprintf("%v", leftVal)
		if rightIndices, exists := rightIndex[key]; exists {
			for _, rightIdx := range rightIndices {
				// Add left columns
				for colName, series := range df.Columns {
					data[colName] = append(data[colName], series.Data[i])
				}

				// Add right columns (except join column)
				for colName, series := range other.Columns {
					if colName != on {
						data[colName] = append(data[colName], series.Data[rightIdx])
					}
				}
			}
		}
	}

	return NewDataFrame(data)
}

// Describe returns summary statistics
func (df *DataFrame) Describe() map[string]map[string]float64 {
	result := make(map[string]map[string]float64)

	for colName, series := range df.Columns {
		if series.Dtype == "float64" || series.Dtype == "int64" {
			stats := make(map[string]float64)
			stats["count"] = float64(series.Len())
			stats["mean"] = series.Mean()
			stats["std"] = series.Std()
			stats["min"] = series.Min()
			stats["max"] = series.Max()
			stats["median"] = series.Median()

			result[colName] = stats
		}
	}

	return result
}

// AddColumn adds a new column to the DataFrame
func (df *DataFrame) AddColumn(name string, data []interface{}) {
	if len(data) != df.NRows {
		panic(fmt.Sprintf("column length %d doesn't match DataFrame rows %d", len(data), df.NRows))
	}

	df.Columns[name] = NewSeriesWithIndex(data, df.Index, name)
	df.NCols++
}

// DropColumn removes a column from the DataFrame
func (df *DataFrame) DropColumn(name string) {
	if _, exists := df.Columns[name]; exists {
		delete(df.Columns, name)
		df.NCols--
	}
}

// RenameColumn renames a column
func (df *DataFrame) RenameColumn(oldName, newName string) {
	if series, exists := df.Columns[oldName]; exists {
		series.Name = newName
		df.Columns[newName] = series
		delete(df.Columns, oldName)
	}
}

// Copy creates a deep copy
func (df *DataFrame) Copy() *DataFrame {
	data := make(map[string][]interface{})

	for colName, series := range df.Columns {
		colCopy := make([]interface{}, len(series.Data))
		copy(colCopy, series.Data)
		data[colName] = colCopy
	}

	return NewDataFrame(data)
}

// ToJSON converts DataFrame to JSON
func (df *DataFrame) ToJSON() (string, error) {
	records := make([]map[string]interface{}, df.NRows)

	for i := 0; i < df.NRows; i++ {
		records[i] = df.GetRow(i)
	}

	jsonData, err := json.Marshal(records)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// ToCSV writes DataFrame to CSV file
func (df *DataFrame) ToCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers
	headers := make([]string, 0, df.NCols)
	for colName := range df.Columns {
		headers = append(headers, colName)
	}
	sort.Strings(headers) // For consistent column order

	if err := writer.Write(headers); err != nil {
		return err
	}

	// Write data rows
	for i := 0; i < df.NRows; i++ {
		row := make([]string, len(headers))
		for j, colName := range headers {
			row[j] = fmt.Sprintf("%v", df.Columns[colName].Data[i])
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ToMap converts DataFrame to map representation
func (df *DataFrame) ToMap() map[string]interface{} {
	columns := make(map[string]interface{})
	for colName, series := range df.Columns {
		columns[colName] = series.Data
	}

	return map[string]interface{}{
		"columns": columns,
		"index":   df.Index,
		"nrows":   df.NRows,
		"ncols":   df.NCols,
	}
}

// GetColumnNames returns all column names
func (df *DataFrame) GetColumnNames() []string {
	names := make([]string, 0, df.NCols)
	for colName := range df.Columns {
		names = append(names, colName)
	}
	sort.Strings(names)
	return names
}

// GroupedDataFrame represents a grouped DataFrame
type GroupedDataFrame struct {
	DF       *DataFrame
	GroupCol string
	Groups   map[interface{}][]int
}

// Aggregate performs aggregation on grouped data
func (gdf *GroupedDataFrame) Aggregate(column string, fn func([]interface{}) interface{}) *DataFrame {
	data := make(map[string][]interface{})
	data[gdf.GroupCol] = make([]interface{}, 0)
	data[column] = make([]interface{}, 0)

	series, exists := gdf.DF.Columns[column]
	if !exists {
		panic(fmt.Sprintf("column %s not found", column))
	}

	// Sort group keys for consistent output
	keys := make([]string, 0, len(gdf.Groups))
	for key := range gdf.Groups {
		keys = append(keys, key.(string))
	}
	sort.Strings(keys)

	for _, key := range keys {
		indices := gdf.Groups[key]

		// Extract values for this group
		values := make([]interface{}, len(indices))
		for i, idx := range indices {
			values[i] = series.Data[idx]
		}

		// Apply aggregation function
		result := fn(values)

		data[gdf.GroupCol] = append(data[gdf.GroupCol], key)
		data[column] = append(data[column], result)
	}

	return NewDataFrame(data)
}

// Count returns the count of items in each group
func (gdf *GroupedDataFrame) Count() *DataFrame {
	data := make(map[string][]interface{})
	data[gdf.GroupCol] = make([]interface{}, 0)
	data["count"] = make([]interface{}, 0)

	// Sort group keys
	keys := make([]string, 0, len(gdf.Groups))
	for key := range gdf.Groups {
		keys = append(keys, key.(string))
	}
	sort.Strings(keys)

	for _, key := range keys {
		data[gdf.GroupCol] = append(data[gdf.GroupCol], key)
		data["count"] = append(data["count"], len(gdf.Groups[key]))
	}

	return NewDataFrame(data)
}

// Sum returns the sum for each group
func (gdf *GroupedDataFrame) Sum(column string) *DataFrame {
	return gdf.Aggregate(column, func(values []interface{}) interface{} {
		sum := 0.0
		for _, val := range values {
			if num, ok := toFloat64(val); ok {
				sum += num
			}
		}
		return sum
	})
}

// Mean returns the mean for each group
func (gdf *GroupedDataFrame) Mean(column string) *DataFrame {
	return gdf.Aggregate(column, func(values []interface{}) interface{} {
		sum := 0.0
		count := 0
		for _, val := range values {
			if num, ok := toFloat64(val); ok {
				sum += num
				count++
			}
		}
		if count == 0 {
			return 0.0
		}
		return sum / float64(count)
	})
}

// FillNA fills null values in all columns
func (df *DataFrame) FillNA(value interface{}) *DataFrame {
	data := make(map[string][]interface{})

	for colName, series := range df.Columns {
		filled := series.FillNA(value)
		data[colName] = filled.Data
	}

	return NewDataFrame(data)
}

// DropNA drops rows with any null values
func (df *DataFrame) DropNA() *DataFrame {
	return df.Filter(func(row map[string]interface{}) bool {
		for _, val := range row {
			if val == nil {
				return false
			}
		}
		return true
	})
}

// Apply applies a function to each row
func (df *DataFrame) Apply(fn func(map[string]interface{}) interface{}) []interface{} {
	result := make([]interface{}, df.NRows)

	for i := 0; i < df.NRows; i++ {
		row := df.GetRow(i)
		result[i] = fn(row)
	}

	return result
}

// Pivot creates a pivot table
func (df *DataFrame) Pivot(index, columns, values string) *DataFrame {
	indexSeries, indexExists := df.Columns[index]
	columnSeries, columnExists := df.Columns[columns]
	valueSeries, valueExists := df.Columns[values]

	if !indexExists || !columnExists || !valueExists {
		panic("pivot columns not found")
	}

	// Get unique values for index and columns
	uniqueIndex := indexSeries.Unique()
	uniqueColumns := columnSeries.Unique()

	// Create result data structure
	data := make(map[string][]interface{})
	data[index] = uniqueIndex

	for _, col := range uniqueColumns {
		colStr := fmt.Sprintf("%v", col)
		data[colStr] = make([]interface{}, len(uniqueIndex))
	}

	// Fill pivot table
	for i := 0; i < df.NRows; i++ {
		idxVal := fmt.Sprintf("%v", indexSeries.Data[i])
		colVal := fmt.Sprintf("%v", columnSeries.Data[i])
		val := valueSeries.Data[i]

		// Find index position
		for j, uIdx := range uniqueIndex {
			if fmt.Sprintf("%v", uIdx) == idxVal {
				data[colVal][j] = val
				break
			}
		}
	}

	return NewDataFrame(data)
}

// Merge is an alias for Join
func (df *DataFrame) Merge(other *DataFrame, on string) *DataFrame {
	return df.Join(other, on)
}

// Sample returns a random sample of n rows
func (df *DataFrame) Sample(n int) *DataFrame {
	if n >= df.NRows {
		return df.Copy()
	}

	// Simple random sampling without replacement
	indices := make([]int, df.NRows)
	for i := range indices {
		indices[i] = i
	}

	// Fisher-Yates shuffle (first n elements)
	for i := 0; i < n; i++ {
		j := i + (len(indices)-i)/2 // Simple deterministic "random"
		indices[i], indices[j] = indices[j], indices[i]
	}

	// Create DataFrame from sampled indices
	data := make(map[string][]interface{})
	for colName, series := range df.Columns {
		newCol := make([]interface{}, n)
		for i := 0; i < n; i++ {
			newCol[i] = series.Data[indices[i]]
		}
		data[colName] = newCol
	}

	return NewDataFrame(data)
}

// Query filters DataFrame using a simple query language
func (df *DataFrame) Query(query string) *DataFrame {
	// Simple query parser: "column op value"
	// Example: "age > 25"
	parts := strings.Fields(query)
	if len(parts) != 3 {
		panic("invalid query format, expected: column op value")
	}

	column := parts[0]
	operator := parts[1]
	value := parts[2]

	if _, exists := df.Columns[column]; !exists {
		panic(fmt.Sprintf("column %s not found", column))
	}

	return df.Filter(func(row map[string]interface{}) bool {
		rowVal := row[column]
		return compareValues(rowVal, operator, value)
	})
}

// compareValues compares two values using an operator
func compareValues(left interface{}, op string, rightStr string) bool {
	leftNum, leftOk := toFloat64(left)
	rightNum, rightOk := toFloat64(rightStr)

	if leftOk && rightOk {
		switch op {
		case ">":
			return leftNum > rightNum
		case ">=":
			return leftNum >= rightNum
		case "<":
			return leftNum < rightNum
		case "<=":
			return leftNum <= rightNum
		case "==":
			return leftNum == rightNum
		case "!=":
			return leftNum != rightNum
		}
	}

	// String comparison
	leftStr := fmt.Sprintf("%v", left)
	switch op {
	case "==":
		return leftStr == rightStr
	case "!=":
		return leftStr != rightStr
	}

	return false
}
