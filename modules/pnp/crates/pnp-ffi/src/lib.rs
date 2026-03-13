//! C FFI bindings for PnP pose estimation.
#![allow(non_camel_case_types)]

use pnp_core::types as core;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;

/// 2D vector.
#[repr(C)]
pub struct pnp_vector2_t {
    pub x: f64,
    pub y: f64,
}

/// 3D vector.
#[repr(C)]
pub struct pnp_vector3_t {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// Quaternion (Hamilton convention: x, y, z, w).
#[repr(C)]
pub struct pnp_quaternion_t {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub w: f64,
}

/// 3x3 matrix in column-major order: m[col*3 + row].
#[repr(C)]
pub struct pnp_matrix3x3_t {
    pub m: [f64; 9],
}

/// Pose (position + rotation).
#[repr(C)]
pub struct pnp_pose_t {
    pub position: pnp_vector3_t,
    pub rotation: pnp_quaternion_t,
}

/// Landmark (3D point with string ID).
#[repr(C)]
pub struct pnp_landmark_t {
    pub id: *const c_char,
    pub position: pnp_vector3_t,
}

/// Landmark observation (2D point with string ID).
#[repr(C)]
pub struct pnp_landmark_observation_t {
    pub id: *const c_char,
    pub position: pnp_vector2_t,
}

/// Solve method enum.
#[repr(C)]
pub enum pnp_method_t {
    PNP_METHOD_EPNP = 0,
    PNP_METHOD_ITERATIVE = 1,
    PNP_METHOD_SQPNP = 2,
}

/// Error codes.
#[repr(C)]
pub enum pnp_error_t {
    PNP_OK = 0,
    PNP_ERROR_INSUFFICIENT_POINTS = 1,
    PNP_ERROR_SOLVER_FAILED = 2,
    PNP_ERROR_MISMATCHED_COUNTS = 3,
    PNP_ERROR_NULL_POINTER = 4,
    PNP_ERROR_INVALID_STRING = 5,
}

/// Result struct returned by solve functions.
#[repr(C)]
pub struct pnp_result_t {
    pub error: pnp_error_t,
    pub pose: pnp_pose_t,
}

fn core_error_to_ffi(e: core::PnpError) -> pnp_error_t {
    match e {
        core::PnpError::InsufficientPoints => pnp_error_t::PNP_ERROR_INSUFFICIENT_POINTS,
        core::PnpError::SolverFailed => pnp_error_t::PNP_ERROR_SOLVER_FAILED,
        core::PnpError::MismatchedCounts => pnp_error_t::PNP_ERROR_MISMATCHED_COUNTS,
    }
}

fn core_pose_to_ffi(p: &core::Pose) -> pnp_pose_t {
    pnp_pose_t {
        position: pnp_vector3_t {
            x: p.position.x,
            y: p.position.y,
            z: p.position.z,
        },
        rotation: pnp_quaternion_t {
            x: p.rotation.x,
            y: p.rotation.y,
            z: p.rotation.z,
            w: p.rotation.w,
        },
    }
}

fn ffi_pose_to_core(p: &pnp_pose_t) -> core::Pose {
    core::Pose::new(
        core::Vector3::new(p.position.x, p.position.y, p.position.z),
        core::Quaternion::new(p.rotation.x, p.rotation.y, p.rotation.z, p.rotation.w),
    )
}

fn zero_pose() -> pnp_pose_t {
    pnp_pose_t {
        position: pnp_vector3_t {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        },
        rotation: pnp_quaternion_t {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        },
    }
}

fn method_to_core(m: pnp_method_t) -> core::SolvePnpMethod {
    match m {
        pnp_method_t::PNP_METHOD_EPNP => core::SolvePnpMethod::EPnP,
        pnp_method_t::PNP_METHOD_ITERATIVE => core::SolvePnpMethod::Iterative,
        pnp_method_t::PNP_METHOD_SQPNP => core::SolvePnpMethod::SQPnP,
    }
}

unsafe fn read_c_str(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
}

/// Solve PnP and return object pose in OpenGL coordinates.
///
/// # Safety
/// `landmarks` must point to `num_landmarks` valid `pnp_landmark_t` structs.
/// `observations` must point to `num_observations` valid `pnp_landmark_observation_t` structs.
/// All `id` pointers within landmarks/observations must be valid null-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pnp_solve(
    landmarks: *const pnp_landmark_t,
    num_landmarks: usize,
    observations: *const pnp_landmark_observation_t,
    num_observations: usize,
    camera_matrix: *const pnp_matrix3x3_t,
    method: pnp_method_t,
) -> pnp_result_t {
    if landmarks.is_null() || observations.is_null() || camera_matrix.is_null() {
        return pnp_result_t {
            error: pnp_error_t::PNP_ERROR_NULL_POINTER,
            pose: zero_pose(),
        };
    }

    let lm_slice = slice::from_raw_parts(landmarks, num_landmarks);
    let obs_slice = slice::from_raw_parts(observations, num_observations);
    let cam = &*camera_matrix;

    let mut core_landmarks = Vec::with_capacity(num_landmarks);
    for lm in lm_slice {
        let id = match read_c_str(lm.id) {
            Some(s) => s,
            None => {
                return pnp_result_t {
                    error: pnp_error_t::PNP_ERROR_INVALID_STRING,
                    pose: zero_pose(),
                };
            }
        };
        core_landmarks.push(core::Landmark {
            id,
            position: core::Vector3::new(lm.position.x, lm.position.y, lm.position.z),
        });
    }

    let mut core_obs = Vec::with_capacity(num_observations);
    for ob in obs_slice {
        let id = match read_c_str(ob.id) {
            Some(s) => s,
            None => {
                return pnp_result_t {
                    error: pnp_error_t::PNP_ERROR_INVALID_STRING,
                    pose: zero_pose(),
                };
            }
        };
        core_obs.push(core::LandmarkObservation {
            id,
            position: core::Vector2::new(ob.position.x, ob.position.y),
        });
    }

    let core_cam = core::Matrix3x3 { m: cam.m };
    let core_method = method_to_core(method);

    match pnp_core::solve_pnp(&core_landmarks, &core_obs, &core_cam, core_method) {
        Ok(pose) => pnp_result_t {
            error: pnp_error_t::PNP_OK,
            pose: core_pose_to_ffi(&pose),
        },
        Err(e) => pnp_result_t {
            error: core_error_to_ffi(e),
            pose: zero_pose(),
        },
    }
}

/// Solve PnP and return camera pose (inverted).
///
/// # Safety
/// Same requirements as `pnp_solve`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pnp_solve_camera_pose(
    landmarks: *const pnp_landmark_t,
    num_landmarks: usize,
    observations: *const pnp_landmark_observation_t,
    num_observations: usize,
    camera_matrix: *const pnp_matrix3x3_t,
    method: pnp_method_t,
) -> pnp_result_t {
    if landmarks.is_null() || observations.is_null() || camera_matrix.is_null() {
        return pnp_result_t {
            error: pnp_error_t::PNP_ERROR_NULL_POINTER,
            pose: zero_pose(),
        };
    }

    let lm_slice = slice::from_raw_parts(landmarks, num_landmarks);
    let obs_slice = slice::from_raw_parts(observations, num_observations);
    let cam = &*camera_matrix;

    let mut core_landmarks = Vec::with_capacity(num_landmarks);
    for lm in lm_slice {
        let id = match read_c_str(lm.id) {
            Some(s) => s,
            None => {
                return pnp_result_t {
                    error: pnp_error_t::PNP_ERROR_INVALID_STRING,
                    pose: zero_pose(),
                };
            }
        };
        core_landmarks.push(core::Landmark {
            id,
            position: core::Vector3::new(lm.position.x, lm.position.y, lm.position.z),
        });
    }

    let mut core_obs = Vec::with_capacity(num_observations);
    for ob in obs_slice {
        let id = match read_c_str(ob.id) {
            Some(s) => s,
            None => {
                return pnp_result_t {
                    error: pnp_error_t::PNP_ERROR_INVALID_STRING,
                    pose: zero_pose(),
                };
            }
        };
        core_obs.push(core::LandmarkObservation {
            id,
            position: core::Vector2::new(ob.position.x, ob.position.y),
        });
    }

    let core_cam = core::Matrix3x3 { m: cam.m };
    let core_method = method_to_core(method);

    match pnp_core::solve_pnp_camera_pose(&core_landmarks, &core_obs, &core_cam, core_method) {
        Ok(pose) => pnp_result_t {
            error: pnp_error_t::PNP_OK,
            pose: core_pose_to_ffi(&pose),
        },
        Err(e) => pnp_result_t {
            error: core_error_to_ffi(e),
            pose: zero_pose(),
        },
    }
}

/// Invert a solvePnP pose to get the camera pose.
#[unsafe(no_mangle)]
pub extern "C" fn pnp_camera_pose_from_solve_pnp_pose(pose: *const pnp_pose_t) -> pnp_pose_t {
    if pose.is_null() {
        return zero_pose();
    }
    let core_pose = ffi_pose_to_core(unsafe { &*pose });
    let result = pnp_core::camera_pose_from_solve_pnp_pose(&core_pose);
    core_pose_to_ffi(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_pnp_solve_basic() {
        let ids: Vec<CString> = (0..4).map(|i| CString::new(i.to_string()).unwrap()).collect();

        let landmarks = [
            pnp_landmark_t {
                id: ids[0].as_ptr(),
                position: pnp_vector3_t { x: -0.15, y: -0.15, z: 0.0 },
            },
            pnp_landmark_t {
                id: ids[1].as_ptr(),
                position: pnp_vector3_t { x: 0.15, y: -0.15, z: 0.0 },
            },
            pnp_landmark_t {
                id: ids[2].as_ptr(),
                position: pnp_vector3_t { x: 0.15, y: 0.15, z: 0.0 },
            },
            pnp_landmark_t {
                id: ids[3].as_ptr(),
                position: pnp_vector3_t { x: -0.15, y: 0.15, z: 0.0 },
            },
        ];

        let observations = [
            pnp_landmark_observation_t {
                id: ids[0].as_ptr(),
                position: pnp_vector2_t { x: 849.3577, y: 461.7641 },
            },
            pnp_landmark_observation_t {
                id: ids[1].as_ptr(),
                position: pnp_vector2_t { x: 1070.642, y: 461.7641 },
            },
            pnp_landmark_observation_t {
                id: ids[2].as_ptr(),
                position: pnp_vector2_t { x: 1096.898, y: 636.8014 },
            },
            pnp_landmark_observation_t {
                id: ids[3].as_ptr(),
                position: pnp_vector2_t { x: 823.1021, y: 636.8014 },
            },
        ];

        // Camera matrix: fx=fy=815.8511, cx=960, cy=540
        let cam = pnp_matrix3x3_t {
            m: [815.8511, 0.0, 0.0, 0.0, 815.8511, 0.0, 960.0, 540.0, 1.0],
        };

        let result = unsafe {
            pnp_solve(
                landmarks.as_ptr(),
                4,
                observations.as_ptr(),
                4,
                &cam,
                pnp_method_t::PNP_METHOD_ITERATIVE,
            )
        };

        assert!(matches!(result.error, pnp_error_t::PNP_OK));
        assert!(!result.pose.position.x.is_nan());
        assert!(!result.pose.rotation.w.is_nan());
    }

    #[test]
    fn test_pnp_solve_null_pointer() {
        let cam = pnp_matrix3x3_t { m: [0.0; 9] };
        let result = unsafe {
            pnp_solve(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &cam,
                pnp_method_t::PNP_METHOD_EPNP,
            )
        };
        assert!(matches!(result.error, pnp_error_t::PNP_ERROR_NULL_POINTER));
    }

    #[test]
    fn test_pnp_camera_pose_inversion() {
        let pose = pnp_pose_t {
            position: pnp_vector3_t { x: 1.0, y: 2.0, z: 3.0 },
            rotation: pnp_quaternion_t { x: 0.0, y: 0.0, z: 0.0, w: 1.0 },
        };
        let cam_pose = pnp_camera_pose_from_solve_pnp_pose(&pose);
        assert!((cam_pose.position.x - (-1.0)).abs() < 1e-10);
        assert!((cam_pose.position.y - (-2.0)).abs() < 1e-10);
        assert!((cam_pose.position.z - (-3.0)).abs() < 1e-10);
    }
}
