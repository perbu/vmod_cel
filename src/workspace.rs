use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::ptr;
use std::slice;
use std::str;
use varnish::vcl::{VclError, Workspace};
use varnish_sys::vcl::StrOrBytes;

/// Workspace-backed string that references memory in Varnish workspace
/// This avoids heap allocations by storing strings directly in the workspace
#[derive(Debug)]
pub struct WsString<'ctx> {
    ptr: *const u8,
    len: usize,
    _phantom: PhantomData<&'ctx str>,
}

impl<'ctx> WsString<'ctx> {
    /// Create a WsString from a raw pointer and length
    ///
    /// # Safety
    /// ptr must point to valid UTF-8 data of the given length that remains
    /// valid for the lifetime 'ctx
    pub unsafe fn from_raw(ptr: *const u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            _phantom: PhantomData,
        }
    }

    /// Create a WsString by copying a string into the workspace
    pub fn new(ws: &mut Workspace<'ctx>, s: &str) -> Result<Self, VclError> {
        if s.is_empty() {
            return Ok(Self {
                ptr: ptr::null(),
                len: 0,
                _phantom: PhantomData,
            });
        }

        // Allocate raw bytes in workspace
        let size = NonZeroUsize::new(s.len()).ok_or_else(|| VclError::String("Empty string size".to_string()))?;
        let buffer = ws.allocate_zeroed(size)?;

        // Copy string data to workspace
        unsafe {
            ptr::copy_nonoverlapping(s.as_ptr(), buffer.as_mut_ptr(), s.len());
        }

        Ok(Self {
            ptr: buffer.as_ptr(),
            len: s.len(),
            _phantom: PhantomData,
        })
    }

    /// Create a WsString from StrOrBytes without heap allocation
    pub fn from_str_or_bytes(
        ws: &mut Workspace<'ctx>,
        value: StrOrBytes<'_>,
    ) -> Result<Self, VclError> {
        match value {
            StrOrBytes::Utf8(s) => Self::new(ws, s),
            StrOrBytes::Bytes(bytes) => {
                // Convert bytes to string, handling invalid UTF-8
                match str::from_utf8(bytes) {
                    Ok(s) => Self::new(ws, s),
                    Err(_) => {
                        // Use lossy conversion for invalid UTF-8
                        let lossy = String::from_utf8_lossy(bytes);
                        Self::new(ws, &lossy)
                    }
                }
            }
        }
    }

    /// Get the string as a &str
    pub fn as_str(&self) -> &'ctx str {
        if self.len == 0 {
            ""
        } else {
            unsafe {
                let slice = slice::from_raw_parts(self.ptr, self.len);
                str::from_utf8_unchecked(slice)
            }
        }
    }

    /// Get the length of the string
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Convert to lowercase by creating a new WsString
    pub fn to_lowercase(&self, ws: &mut Workspace<'ctx>) -> Result<WsString<'ctx>, VclError> {
        let lowercase = self.as_str().to_lowercase();
        WsString::new(ws, &lowercase)
    }
}

impl AsRef<str> for WsString<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<str> for WsString<'_> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for WsString<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<'ctx> PartialEq<WsString<'ctx>> for WsString<'ctx> {
    fn eq(&self, other: &WsString<'ctx>) -> bool {
        self.as_str() == other.as_str()
    }
}

/// Workspace-backed key-value storage using linear arrays
/// This replaces HashMap to avoid heap allocations
#[derive(Debug)]
pub struct WsHashMap<'ctx> {
    entries: &'ctx mut [(WsString<'ctx>, WsString<'ctx>)],
    count: usize,
}

impl<'ctx> WsHashMap<'ctx> {
    /// Create a new WsHashMap with the given capacity
    pub fn new(ws: &mut Workspace<'ctx>, capacity: usize) -> Result<Self, VclError> {
        if capacity == 0 {
            return Ok(Self {
                entries: &mut [],
                count: 0,
            });
        }

        // Calculate size needed for the array
        let entry_size = std::mem::size_of::<(WsString<'ctx>, WsString<'ctx>)>();
        let total_size = entry_size * capacity;

        let size = NonZeroUsize::new(total_size).ok_or_else(|| VclError::String("Invalid size for workspace allocation".to_string()))?;
        let buffer = ws.allocate_zeroed(size)?;

        // Cast the buffer to our entry type
        let entries = unsafe {
            let ptr = buffer.as_mut_ptr() as *mut (WsString<'ctx>, WsString<'ctx>);
            slice::from_raw_parts_mut(ptr, capacity)
        };

        Ok(Self { entries, count: 0 })
    }

    /// Insert a key-value pair
    pub fn insert(
        &mut self,
        key: WsString<'ctx>,
        value: WsString<'ctx>,
    ) -> Result<(), VclError> {
        if self.count >= self.entries.len() {
            return Err(VclError::String("WsHashMap capacity exceeded".to_string())); // Out of capacity
        }

        // Check if key already exists and update if so
        for entry in &mut self.entries[..self.count] {
            if entry.0 == key {
                entry.1 = value;
                return Ok(());
            }
        }

        // Add new entry
        self.entries[self.count] = (key, value);
        self.count += 1;
        Ok(())
    }

    /// Get a value by key (case-insensitive for HTTP headers)
    pub fn get(&self, key: &str) -> Option<&WsString<'ctx>> {
        for entry in &self.entries[..self.count] {
            if entry.0.as_str().eq_ignore_ascii_case(key) {
                return Some(&entry.1);
            }
        }
        None
    }

    /// Check if a key exists (case-insensitive)
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over entries
    pub fn iter(&self) -> impl Iterator<Item = (&WsString<'ctx>, &WsString<'ctx>)> {
        self.entries[..self.count].iter().map(|(k, v)| (k, v))
    }
}

/// Configuration for workspace allocation
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Maximum number of headers to allocate space for
    pub max_headers: usize,

    /// Maximum number of cookies to allocate space for
    pub max_cookies: usize,

    /// Maximum size for individual strings
    pub max_string_size: usize,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            max_headers: 50,
            max_cookies: 20,
            max_string_size: 8192,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_config() {
        let config = WorkspaceConfig::default();
        assert_eq!(config.max_headers, 50);
        assert_eq!(config.max_cookies, 20);
        assert_eq!(config.max_string_size, 8192);
    }

    // Note: Other tests would require a Varnish context, so they're better
    // placed in integration tests with actual Varnish workspace
}