package ws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRingBuffer_AddAndLast(t *testing.T) {
	rb := NewRingBuffer(3)

	rb.Add([]byte("a"))
	rb.Add([]byte("b"))
	rb.Add([]byte("c"))

	items := rb.Last(10)
	require.Len(t, items, 3)
	require.Equal(t, "a", string(items[0]))
	require.Equal(t, "b", string(items[1]))
	require.Equal(t, "c", string(items[2]))
}

func TestRingBuffer_AddEvictsOldest(t *testing.T) {
	rb := NewRingBuffer(2)

	rb.Add([]byte("a"))
	rb.Add([]byte("b"))
	rb.Add([]byte("c")) // should evict "a"

	items := rb.Last(10)
	require.Len(t, items, 2)
	require.Equal(t, "b", string(items[0]))
	require.Equal(t, "c", string(items[1]))
}

func TestRingBuffer_LastN(t *testing.T) {
	rb := NewRingBuffer(5)
	rb.Add([]byte("1"))
	rb.Add([]byte("2"))
	rb.Add([]byte("3"))

	items := rb.Last(2)
	require.Len(t, items, 2)
	require.Equal(t, "2", string(items[0]))
	require.Equal(t, "3", string(items[1]))
}

func TestRingBuffer_LastMoreThanAvailable(t *testing.T) {
	rb := NewRingBuffer(5)
	rb.Add([]byte("only"))

	items := rb.Last(10)
	require.Len(t, items, 1)
	require.Equal(t, "only", string(items[0]))
}

func TestRingBuffer_Clear(t *testing.T) {
	rb := NewRingBuffer(5)
	rb.Add([]byte("a"))
	rb.Add([]byte("b"))

	rb.Clear()

	items := rb.Last(10)
	require.Len(t, items, 0)
}

func TestRingBuffer_ClearEmpty(t *testing.T) {
	rb := NewRingBuffer(5)
	rb.Clear() // should not panic

	items := rb.Last(10)
	require.Len(t, items, 0)
}

func TestRingBuffer_AddDoesNotMutateOriginal(t *testing.T) {
	rb := NewRingBuffer(3)
	data := []byte("original")
	rb.Add(data)
	data[0] = 'x' // mutate original slice

	items := rb.Last(1)
	require.Equal(t, "original", string(items[0]))
}
