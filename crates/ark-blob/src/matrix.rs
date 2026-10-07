use crate::error::{BlobError, Result};
use crate::gf::GF;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<u8>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0; rows * cols],
        }
    }

    pub fn identity(size: usize) -> Self {
        let mut m = Self::new(size, size);
        for i in 0..size {
            m.set(i, i, 1);
        }
        m
    }

    #[inline(always)]
    pub fn get(&self, r: usize, c: usize) -> u8 {
        self.data[r * self.cols + c]
    }

    #[inline(always)]
    pub fn set(&mut self, r: usize, c: usize, val: u8) {
        self.data[r * self.cols + c] = val;
    }

    /// Cauchy matrix construction: A_{i, j} = 1 / (X_i ^ Y_j).
    /// Standard canonical choice for disjoint sets in GF(2^8):
    /// X_i = i, Y_j = j + rows (or offset such that X_i != Y_j).
    /// For k data rows and m parity rows:
    /// In Cauchy Reed-Solomon generator matrix, the top k x k is Identity matrix,
    /// and bottom m x k is Cauchy matrix where Cauchy_{i, j} = 1 / (X_i ^ Y_j).
    /// With X_i = i (i in 0..m) and Y_j = m + j (j in 0..k).
    /// Since i < m <= 4 and m + j in 4..14, X_i and Y_j are completely disjoint,
    /// guaranteeing X_i ^ Y_j != 0.
    pub fn cauchy(rows: usize, cols: usize) -> Self {
        let mut m = Self::new(rows, cols);
        for i in 0..rows {
            let x = i as u8;
            for j in 0..cols {
                let y = (rows + j) as u8;
                let diff = x ^ y;
                assert!(diff != 0, "Cauchy sets X and Y must be disjoint");
                let inv = GF.inv(diff);
                m.set(i, j, inv);
            }
        }
        m
    }

    /// Matrix multiplication: self * other in GF(2^8)
    pub fn mul(&self, other: &Matrix) -> Matrix {
        assert_eq!(self.cols, other.rows);
        let mut res = Matrix::new(self.rows, other.cols);
        for r in 0..self.rows {
            for c in 0..other.cols {
                let mut sum = 0u8;
                for k in 0..self.cols {
                    sum ^= GF.mul(self.get(r, k), other.get(k, c));
                }
                res.set(r, c, sum);
            }
        }
        res
    }

    /// Invert an n x n square matrix in GF(2^8) using Gaussian elimination.
    pub fn invert(&self) -> Result<Matrix> {
        if self.rows != self.cols {
            return Err(BlobError::SingularMatrix);
        }
        let n = self.rows;
        let mut work = self.clone();
        let mut inv = Matrix::identity(n);

        for col in 0..n {
            // Find pivot
            let mut pivot_row = None;
            for r in col..n {
                if work.get(r, col) != 0 {
                    pivot_row = Some(r);
                    break;
                }
            }

            let pivot_row = pivot_row.ok_or(BlobError::SingularMatrix)?;

            // Swap rows if needed
            if pivot_row != col {
                for c in 0..n {
                    let w_temp = work.get(col, c);
                    work.set(col, c, work.get(pivot_row, c));
                    work.set(pivot_row, c, w_temp);

                    let i_temp = inv.get(col, c);
                    inv.set(col, c, inv.get(pivot_row, c));
                    inv.set(pivot_row, c, i_temp);
                }
            }

            // Scale pivot row so work[col, col] == 1
            let pivot_val = work.get(col, col);
            let pivot_inv = GF.inv(pivot_val);

            for c in 0..n {
                work.set(col, c, GF.mul(work.get(col, c), pivot_inv));
                inv.set(col, c, GF.mul(inv.get(col, c), pivot_inv));
            }

            // Eliminate all other rows
            for r in 0..n {
                if r != col {
                    let factor = work.get(r, col);
                    if factor != 0 {
                        for c in 0..n {
                            let w_sub = GF.mul(factor, work.get(col, c));
                            work.set(r, c, work.get(r, c) ^ w_sub);

                            let i_sub = GF.mul(factor, inv.get(col, c));
                            inv.set(r, c, inv.get(r, c) ^ i_sub);
                        }
                    }
                }
            }
        }

        Ok(inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_inverse() {
        let mut m = Matrix::new(3, 3);
        m.set(0, 0, 1); m.set(0, 1, 2); m.set(0, 2, 3);
        m.set(1, 0, 0); m.set(1, 1, 4); m.set(1, 2, 5);
        m.set(2, 0, 1); m.set(2, 1, 0); m.set(2, 2, 6);

        let inv = m.invert().expect("inversion should succeed");
        let identity = m.mul(&inv);

        assert_eq!(identity, Matrix::identity(3));
    }

    #[test]
    fn test_cauchy_matrix() {
        let cauchy = Matrix::cauchy(4, 10);
        assert_eq!(cauchy.rows, 4);
        assert_eq!(cauchy.cols, 10);
        for r in 0..4 {
            for c in 0..10 {
                assert_ne!(cauchy.get(r, c), 0);
            }
        }
    }
}
