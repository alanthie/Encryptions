///\author Sean Malloy
///\name	 matrix.hpp
///\brief  Generic matrix class for performing various matrix operations.

#include "matrix.hpp"

namespace mat
{
  /**********************************************************************/
  // Global functions

  bool
  almostEqual(elem_t a, elem_t b)
  {
    elem_t diff = std::fabs(a - b);
    return diff <= std::numeric_limits<elem_t>::epsilon();
  }

  // matrix addition
  matrix
  operator+(const matrix& A, const matrix& B)
  {
    return (matrix) A += B;
  }

  matrix
  operator-(const matrix& A, const matrix& B)
  {
    return (matrix) A -= B;
  }

  matrix
  operator-(const matrix& A)
  {
    return (matrix) A *= -1;
  }

  // matrix multiplication
  matrix
  operator*(const matrix& A, const matrix& B)
  {
    return (matrix) A *= B;
  }

  // scalar multiplication
  matrix
  operator*(elem_t k, const matrix& A)
  {
    return (matrix) A *= k;
  }

  matrix
  operator*(const matrix& A, elem_t k)
  {
    return (matrix) A *= k;
  }

  matrix
  operator^(const matrix& A, unsigned long k)
  {
    return (matrix) A ^= k;
  }

  std::ostream&
  operator<<(std::ostream& output, const matrix& A)
  {
    output << std::left;
    for (size_t i = 0; i < A.rows(); ++i)
    {
      for (size_t j = 0; j < A.cols(); ++j)
        output << std::setw(10) << A(i, j) << ' ';
      output << '\n';
    }

    return output;
  }

  bool
  operator==(const matrix& A, const matrix& B)
  {
    if (A.rows() != B.rows() || A.cols() != B.cols())
      return false;

    for (size_t i = 0; i < A.rows(); ++i)
      for (size_t j = 0; j < A.cols(); ++j)
        if (!almostEqual(A(i, j), B(i, j)))
          return false;

    return true;
  }

  bool
  operator!=(const matrix& A, const matrix& B)
  {
    return !(A == B);
  }

  // Gaussian elimination
  matrix
  rowEchelon(matrix A)
  {
    if (A.isRowEchelonForm())
      return A;

    for (size_t currTopRow = 0; currTopRow < A.rows(); ++currTopRow)
    {
      size_t currRow = currTopRow;
      size_t currCol = 0;

      bool found = false;
      for (size_t j = 0; j < A.cols(); ++j)
      {
        for (size_t i = currTopRow; i < A.rows(); ++i)
        {
          if (A(i, j) != 0)
          {
            found = true;
            currRow = i;
            currCol = j;
            break;
          }
        }

        if (found)
          break;
      }

      if (!found)
        return A;

      if (currRow != currTopRow)
      {
        A.swapRows(currRow, currTopRow);
        currRow = currTopRow;
      }

      elem_t leadingElement = A(currRow, currCol);
      if (leadingElement != 1)
        A.multiplyRow(currRow, 1.0 / leadingElement);

      for (size_t i = currRow + 1; i < A.rows(); ++i)
      {
        elem_t elem = A(i, currCol);
        if (elem != 0)
          A.addRows(currRow, i, -elem);
      }
    }

    return A;
  }

  // Gauss-Jordan elimination
  matrix
  reducedRowEchelon(matrix A)
  {
    A = rowEchelon(A);

    for (size_t currBottomRow = A.rows() - 1; currBottomRow > 0; --currBottomRow)
    {
      bool allZeros = true;
      size_t leadingOne = 0;
      for (size_t j = 0; j < A.cols(); ++j)
      {
        if (A(currBottomRow, j) != 0)
        {
          allZeros = false;
          leadingOne = j;
          break;
        }
      }

      if (!allZeros)
        for (size_t i = 0; i < currBottomRow; ++i)
          A.addRows(currBottomRow, i, -A(i, leadingOne));
    }

    return A;
  }

  matrix
  transpose(const matrix& A)
  {
    matrix transposed(A.cols(), A.rows());

    for (size_t i = 0; i < A.rows(); ++i)
      for (size_t j = 0; j < A.cols(); ++j)
        transposed(j, i) = A(i, j);

    return transposed;
  }

  matrix
  minorMatrix(const matrix& A, size_t r, size_t c)
  {
    if (A.rows() == 1 || A.cols() == 1)
      return A;

    matrix M = matrix(A.rows() - 1, A.cols() - 1);
    auto it = M.begin();

    for (size_t i = 0; i < A.rows(); ++i)
      for (size_t j = 0; j < A.cols(); ++j)
        if (i != r && j != c)
          *(it++) = A(i, j);

    return M;
  }

  elem_t
  determinant(const matrix& A)
  {
    if (A.rows() != A.cols())
    {
      std::cerr << "Determinant not defined, returning 0\n";
      return 0;
    }

    if (A.rows() == 2)
      return (A(0, 0) * A(1, 1)) - (A(0, 1) * A(1, 0));

    elem_t det = 0, sign = 1;
    for (size_t j = 0; j < A.cols(); ++j)
    {
      det += sign * A(0, j) * determinant(minorMatrix(A, 0, j));
      sign *= -1;
    }

    return det;
  }

  matrix
  adjugate(const matrix& A)
  {
    matrix C(A.rows(), A.cols());
    elem_t sign = 1;
    for (size_t i = 0; i < C.rows(); ++i)
    {
      for (size_t j = 0; j < C.cols(); ++j)
      {
        C(i, j) = sign * determinant(minorMatrix(A, i, j));
        sign *= -1;
      }
      sign *= -1;
    }

    return mat::transpose(C);
  }

  matrix
  inverse(matrix& A)
  {
    if (A.rows() != A.cols() || determinant(A) == 0)
    {
      std::cerr << "Inverse does not exist.\n";
      return A;
    }

    matrix augmented(A.rows(), 2 * A.cols());

    for (size_t i = 0; i < A.rows(); ++i)
    {
      for (size_t j = 0; j < A.cols(); ++j)
        augmented(i, j) = A(i, j);

      for (size_t j = A.cols(); j < augmented.cols(); ++j)
        augmented(i, j) = j - A.cols() == i;
    }

    matrix reduced = reducedRowEchelon(augmented);
    matrix inverse(A.rows(), A.cols());

    for (size_t i = 0; i < reduced.rows(); ++i)
      for (size_t j = A.cols(); j < reduced.cols(); ++j)
        inverse(i, j - A.cols()) = reduced(i, j);

    return inverse;
  }

  matrix
  augment(const matrix& A, const matrix& B)
  {
    if (A.rows() != B.rows())
    {
      std::cerr << "Number of rows not equal.\n";
      return A;
    }

    matrix augmented(A.rows(), A.cols() + B.cols());

    for (size_t i = 0; i < A.rows(); ++i)
    {
      size_t j;
      for (j = 0; j < A.cols(); ++j)
        augmented(i, j) = A(i, j);
      for ( ; j < augmented.cols(); ++j)
        augmented(i, j) = B(i, j - A.cols());
    }

    return augmented;
  }

  matrix
  identity(size_t size)
  {
    mat::matrix A(size, size);
    for (size_t i = 0; i < A.rows(); ++i)
      for (size_t j = 0; j < A.cols(); ++j)
        A(i, j) = i == j;

    return A;
  }

  matrix
  zero(size_t rows, size_t cols)
  {
    return matrix(rows, cols, 0);
  }

  elem_t
  rowLength(size_t row, matrix A)
  {
    elem_t sum = 0;
    for (size_t j = 0; j < A.cols(); ++j)
      sum += A(row, j);
    return sqrt(sum);
  }

  matrix
  cholesky(matrix A)
  {
    // Use row adds to get matrix to be upper triangular
    // Divide each row by the diagonal entry in that row
    for (size_t i = 0; i < A.cols(); ++i)
    {
      for (size_t j = i + 1; j < A.rows(); ++j)
        A.addRows(i, j, -A(j,i)/A(i,i));
      A.multiplyRow(i, 1 / sqrt(A(i,i)));
    }

    return A;
  }
} // namespace mat


