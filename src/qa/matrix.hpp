#ifndef MATRIX_MAT_HPP_INCLUDED
#define MATRIX_MAT_HPP_INCLUDED

///\author Sean Malloy
///\name	 matrix.hpp
///\brief  Generic matrix class for performing various matrix operations.


/**********************************************************************/
// System includes
#include <iostream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <cmath>
#include <tuple>
#include <algorithm>

/**********************************************************************/
typedef long long elem_t;

namespace mat
{
  class matrix
  {
  public:
    // type aliases
    using iterator = elem_t*;
    using const_iterator = const elem_t*;

    // default ctor
    matrix()
      : m_rows(0),
        m_cols(0),
        m_size(0),
        m_matrix(nullptr)
    {
    }

    // size ctor
    matrix(size_t rows, size_t cols)
      : m_rows(rows),
        m_cols(cols),
        m_size(rows * cols),
        m_matrix(new elem_t[m_size])
    {
    }

    // size ctor
    matrix(size_t rows, size_t cols, elem_t init)
      : m_rows(rows),
        m_cols(cols),
        m_size(rows * cols),
        m_matrix(new elem_t[m_size])
    {
      for (auto& elem : *this)
        elem = init;
    }

    // copy ctor
    matrix(const matrix& m)
      : m_rows(m.rows()),
        m_cols(m.cols()),
        m_size(m.size()),
        m_matrix(new elem_t[m_size])
    {
      if (this != &m)
        std::copy(m.begin(), m.end(), begin());
    }

    // dtor
    ~matrix()
    {
      if (m_matrix != nullptr)
        delete[] m_matrix;
    }

    matrix&
    operator=(const matrix& m)
    {
      if (this != &m)
      {
        if (m_matrix != nullptr)
          delete[] m_matrix;
        m_matrix = new elem_t[m.rows() * m.cols()];

        std::copy(m.begin(), m.end(), begin());
        m_size = m.size();
        m_rows = m.rows();
        m_cols = m.cols();
      }

      return *this;
    }

    size_t
    rows()
    {
      return m_rows;
    }

    size_t
    rows() const
    {
      return m_rows;
    }

    size_t
    cols()
    {
      return m_cols;
    }

    size_t
    cols() const
    {
      return m_cols;
    }

    size_t
    size()
    {
      return m_size;
    }

    size_t
    size() const
    {
      return m_size;
    }

    iterator
    begin()
    {
      return m_matrix;
    }

    const_iterator
    begin() const
    {
      return m_matrix;
    }

    iterator
    end()
    {
      return m_matrix + m_size;
    }

    const_iterator
    end() const
    {
      return m_matrix + m_size;
    }

    void
    swapRows(size_t r1, size_t r2)
    {
      if (r1 >= m_rows || r2 >= m_rows)
        return;
      for (size_t j = 0; j < m_cols; ++j)
        std::swap((*this)(r1, j), (*this)(r2, j));
    }

    // Adds scalar * r1 to r2, changing the values in r2
    void
    addRows(size_t r1, size_t r2, elem_t scalar = 1)
    {
      if (r1 >= m_rows || r2 >= m_rows)
        return;
      for (size_t j = 0; j < m_cols; ++j)
      {
        if (almostEqual((*this)(r2, j), -scalar * (*this)(r1, j)))
          (*this)(r2, j) = 0;
        else
          (*this)(r2, j) += scalar * (*this)(r1, j);
      }
    }

    void
    multiplyRow(size_t r, elem_t scalar)
    {
      for (size_t j = 0; j < m_cols; ++j)
        if ((*this)(r, j) != 0)
          (*this)(r, j) *= scalar;
    }

    void
    zero()
    {
      for (auto& elem : *this)
        elem = 0;
    }

    elem_t&
    operator()(const size_t& row, const size_t& col)
    {
      return m_matrix[(m_cols * row) + col];
    }

    elem_t
    operator()(const size_t& row, const size_t& col) const
    {
      return m_matrix[(m_cols * row) + col];
    }

    // matrix addition
    matrix&
    operator+=(const matrix& other)
    {
      if (m_rows == other.rows() && m_cols == other.cols())
      {
        for (size_t i = 0; i < other.rows(); ++i)
          for (size_t j = 0; j < other.cols(); ++j)
            (*this)(i, j) += other(i, j);
      }
      else
        std::cerr << "Incompatible matrices, cannot add";


      return *this;
    }

    // matrix subtraction
    matrix&
    operator-=(const matrix& other)
    {
      if (m_rows == other.rows() && m_cols == other.cols())
      {
        for (size_t i = 0; i < other.rows(); ++i)
          for (size_t j = 0; j < other.cols(); ++j)
            (*this)(i, j) -= other(i, j);
      }

      return *this;
    }

    // matrix multiplication
    matrix&
    operator*=(const matrix& other)
    {
      if (m_cols == other.rows())
      {
        matrix result(m_rows, other.cols(), elem_t(0));
        for (size_t i = 0; i < result.rows(); ++i)
          for (size_t j = 0; j < result.cols(); ++j)
            for (size_t k = 0; k < m_cols; ++k)
              result(i, j) += (*this)(i, k) * other(k, j);

        *this = result;
      }
      else
        std::cerr << "Cannot multiply, returning first matrix\n";

      return *this;
    }

    // Scalar multiplication
    matrix&
    operator*=(elem_t k)
    {
      for (auto& elem : *this)
        if (elem != 0)
          elem *= k;

      return *this;
    }

    matrix&
    operator^=(unsigned long k)
    {
      matrix res = *this;
      for (unsigned long i = 1; i < k; ++i)
        res *= *this;

      *this = res;
      return *this;
    }

    bool
    isRowEchelonForm() const
    {
      size_t prevCol = 0;
      for (size_t i = 0; i < m_rows; ++i)
      {
        for (size_t j = 0; j < m_cols; ++j)
        {
          elem_t elem = (*this)(i, j);
          if (elem == 1 && j > prevCol)
          {
            prevCol = j;
            break;
          }
          else if (elem != 0)
            return false;
        }
      }

      return true;
    }

    bool
    isZeroMatrix() const
    {
      for (const auto& elem : *this)
        if (elem != 0)
          return false;
      return true;
    }

  private:
    size_t m_rows;
    size_t m_cols;
    size_t m_size;

    elem_t* m_matrix;

    bool
    almostEqual(elem_t a, elem_t b)
    {
      elem_t diff = (elem_t)std::fabs(a - b);
      return diff <= std::numeric_limits<elem_t>::epsilon();
    }
  };
  
} // namespace mat
#endif // MATRIX_MAT

