#!/usr/bin/env python3

"""
This file is adapted from https://github.com/undone37/smb-change-monitor
Thanks undone37!
"""

"""
SMB Change Notification Monitor

A Python script that monitors file system changes on Windows SMB shares in real-time
using the smbprotocol library. This script demonstrates how to properly handle
SMB2 CHANGE_NOTIFY requests and parse FILE_NOTIFY_INFORMATION responses.

Key Features:
- Real-time monitoring of file/directory changes on SMB shares
- Comprehensive change detection (create, delete, modify, rename, etc.)
- Manual parsing of SMB2 responses to handle all action codes
- Support for all Microsoft-documented notification types
- Robust error handling and logging

Requirements:
- Python >= 3.8
- smbprotocol library: pip install smbprotocol

Usage:
    python3 watch_smb_changes.py

Configuration:
    Edit the SERVER, SHARE, USERNAME, PASSWORD constants below to match your environment.

Author: undone37, Based on Microsoft SMB2 specifications
License: MIT
References:
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9
"""

import struct
import tomllib
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open

# Use constants directly, no need to import FileAttributes
from smbprotocol.open import (
    CreateOptions,
    CreateDisposition,
    ImpersonationLevel,
    ShareAccess,
)
from smbprotocol.change_notify import (
    SMB2ChangeNotifyRequest,
    ChangeNotifyFlags,
    CompletionFilter,
)
from smbprotocol.open import DirectoryAccessMask, FileAttributes

# =============================================================================
# CONFIGURATION SECTION
# =============================================================================
# Edit these values to match your SMB server configuration

with open("./config.toml", "rb") as f:
    data = tomllib.load(f)

SERVER = data["server"]  # SMB server IP address or hostname
SHARE = data["share"]  # SMB share name (without \\server\ prefix)
USERNAME = data["username"]  # SMB username
PASSWORD = data["password"]  # SMB password

# =============================================================================
# SMB PROTOCOL CONSTANTS
# =============================================================================
# Manually defined constants from Microsoft documentation (MS-FSCC)
FILE_LIST_DIRECTORY = 0x00000001  # Permission to list directory contents
FILE_ATTRIBUTE_DIRECTORY = 0x00000010  # File attribute for directories
WATCH_TREE = True  # Monitor subdirectories recursively

# Comprehensive completion filter to capture all possible file system changes
# See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c
COMPLETION_FILTER = (
    CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME  # 0x00000001 - File name changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_DIR_NAME  # 0x00000002 - Directory name changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_ATTRIBUTES  # 0x00000004 - File attributes change
    | CompletionFilter.FILE_NOTIFY_CHANGE_SIZE  # 0x00000008 - File size changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_CREATION  # 0x00000040 - Creation time changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_EA  # 0x00000080 - Extended attributes change
    | CompletionFilter.FILE_NOTIFY_CHANGE_SECURITY  # 0x00000100 - Security/ACL changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_NAME  # 0x00000200 - Named stream added
    | CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_SIZE  # 0x00000400 - Named stream size changes
    | CompletionFilter.FILE_NOTIFY_CHANGE_STREAM_WRITE  # 0x00000800 - Named stream modified
)

# Complete mapping of all documented FILE_ACTION codes from Microsoft specification
# See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9
ACTION_MAP = {
    0x00000001: "ADDED",  # FILE_ACTION_ADDED
    0x00000002: "REMOVED",  # FILE_ACTION_REMOVED
    0x00000003: "MODIFIED",  # FILE_ACTION_MODIFIED
    0x00000004: "RENAMED_OLD_NAME",  # FILE_ACTION_RENAMED_OLD_NAME
    0x00000005: "RENAMED_NEW_NAME",  # FILE_ACTION_RENAMED_NEW_NAME
    0x00000006: "ADDED_STREAM",  # FILE_ACTION_ADDED_STREAM
    0x00000007: "REMOVED_STREAM",  # FILE_ACTION_REMOVED_STREAM
    0x00000008: "MODIFIED_STREAM",  # FILE_ACTION_MODIFIED_STREAM
    0x00000009: "REMOVED_BY_DELETE",  # FILE_ACTION_REMOVED_BY_DELETE
    0x0000000A: "ID_NOT_TUNNELLED",  # FILE_ACTION_ID_NOT_TUNNELLED
    0x0000000B: "TUNNELLED_ID_COLLISION",  # FILE_ACTION_TUNNELLED_ID_COLLISION
}


def parse_notify_buffer(buffer: bytes) -> list[tuple[int, str]]:
    """
    Manually parses the FILE_NOTIFY_INFORMATION buffer from an SMB2 ChangeNotify response.

    This function bypasses the smbprotocol library's built-in parsing to avoid ValueErrors
    when the server sends action codes that aren't defined in the library's enums.

    The buffer structure follows Microsoft's SMB2 specification:

    1. SMB2 Change Notify Response header (8 bytes):
       - StructureSize (2 bytes): Always 9 for change notify responses
       - OutputBufferOffset (2 bytes): Offset to the actual notification data
       - OutputBufferLength (4 bytes): Length of the notification data

    2. One or more FILE_NOTIFY_INFORMATION structures:
       - NextEntryOffset (4 bytes): Offset to next entry, 0 if last entry
       - Action (4 bytes): Type of change that occurred (see ACTION_MAP)
       - FileNameLength (4 bytes): Length of the filename in bytes
       - FileName (variable): UTF-16LE encoded filename

    Args:
        buffer (bytes): Raw response buffer from SMB2 CHANGE_NOTIFY response

    Returns:
        list[tuple[int, str]]: List of (action_code, filename) tuples

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9
    """
    if len(buffer) < 8:
        print(
            f"[ERROR] Buffer too short ({len(buffer)} bytes) for SMB2 Change Notify Response header."
        )
        return []

    # Parse the SMB2 Change Notify Response header (first 8 bytes)
    # Format: <HHI = little-endian unsigned short, unsigned short, unsigned int
    structure_size, output_buffer_offset, output_buffer_length = struct.unpack_from(
        "<HHI", buffer, 0
    )

    # The actual FILE_NOTIFY_INFORMATION data starts after the 8-byte header
    data_start = 8  # Skip the SMB2 Change Notify Response header

    if data_start >= len(buffer):
        print("[ERROR] No FILE_NOTIFY_INFORMATION data found after header.")
        return []

    notifications = []
    offset = data_start

    # Parse each FILE_NOTIFY_INFORMATION structure in the buffer
    while offset < len(buffer):
        # Unpack the fixed-size part of the FILE_NOTIFY_INFORMATION structure
        # Format: <III = little-endian unsigned int, unsigned int, unsigned int
        try:
            next_offset, action, name_len = struct.unpack_from("<III", buffer, offset)
        except struct.error:
            print(
                f"[ERROR] Could not unpack FILE_NOTIFY_INFORMATION structure at offset {offset}. Malformed buffer?"
            )
            break

        # Calculate filename position: starts after the 12-byte FILE_NOTIFY_INFORMATION header
        name_start = offset + 12
        name_end = name_start + name_len

        # Validate that filename doesn't exceed buffer boundaries
        if name_end > len(buffer):
            print(
                f"[ERROR] FileNameLength ({name_len}) points beyond buffer size. Malformed entry."
            )
            break

        # Extract and decode the filename from UTF-16LE
        filename_bytes = buffer[name_start:name_end]
        filename = filename_bytes.decode("utf-16-le", errors="replace")

        # Add this notification to our results
        notifications.append((action, filename))

        # If NextEntryOffset is 0, this is the last entry in the buffer
        if next_offset == 0:
            break

        # Move to the next entry - NextEntryOffset is relative to current entry start
        offset += next_offset

    return notifications


def watch(callback):
    """
    Main function that establishes SMB connection and monitors file changes.

    This function:
    1. Connects to the SMB server and authenticates
    2. Opens a handle to the root directory of the share
    3. Enters an infinite loop to monitor changes
    4. Processes and displays file system notifications
    5. Handles cleanup on exit
    """
    import uuid as _uuid

    # Establish SMB connection with unique client GUID
    print(f"Connecting to SMB server {SERVER}...")
    conn = Connection(_uuid.uuid4(), SERVER, 445)
    conn.dialect = 0x0311
    conn.connect(dialect=0x0311)

    # Authenticate with the SMB server
    print(f"Authenticating as {USERNAME}...")
    sess = Session(conn, USERNAME, PASSWORD, require_encryption=False)
    sess.connect()

    # Connect to the specified share
    print(f"Connecting to share {SHARE}...")
    tree = TreeConnect(sess, rf"\\{SERVER}\{SHARE}")
    tree.connect()

    # Open a handle to the root directory of the share for monitoring
    # This handle will be used to register for change notifications
    root = Open(tree, "")  # Empty string = share root
    root.create(
        desired_access=FILE_LIST_DIRECTORY,  # Permission to list directory contents
        impersonation_level=ImpersonationLevel.Impersonation,
        # ShareAccess: What OTHER processes are allowed to do while we have the directory open
        # We want to be "invisible" - allow all normal file operations to continue
        share_access=(
            ShareAccess.FILE_SHARE_READ  # Allow other processes to read
            | ShareAccess.FILE_SHARE_WRITE  # Allow other processes to write
            | ShareAccess.FILE_SHARE_DELETE  # Allow other processes to delete
        ),
        file_attributes=FILE_ATTRIBUTE_DIRECTORY,  # This is a directory
        create_options=CreateOptions.FILE_DIRECTORY_FILE,  # Directory-specific options
        create_disposition=CreateDisposition.FILE_OPEN,  # Open existing directory
    )

    # Main monitoring loop - runs indefinitely until interrupted
    print("Starting to watch for changes...")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 50)

    while True:
        try:
            # Create a manual SMB2 CHANGE_NOTIFY request
            # We use manual creation to have full control over the request parameters
            req = SMB2ChangeNotifyRequest()

            # Set flags for recursive monitoring if enabled
            if WATCH_TREE:
                req["flags"] = ChangeNotifyFlags.SMB2_WATCH_TREE

            # Specify which directory to monitor (using our opened handle)
            req["file_id"] = root.file_id

            # Set the types of changes we want to be notified about
            req["completion_filter"] = COMPLETION_FILTER

            # Set maximum buffer size for the response (64KB should be sufficient)
            req["output_buffer_length"] = 65536  # 64KB

            # Send the request and wait for a response (this call blocks until a change occurs)
            # The server will hold this request open until a file system change happens
            # print("Waiting for a change notification from the server...")
            request = tree.session.connection.send(
                req, sid=tree.session.session_id, tid=tree.tree_connect_id
            )
            response = tree.session.connection.receive(request)
            # print("Change notification received. Parsing response...")

            # Extract the raw notification data from the response
            # The 'data' field contains the SMB2 Change Notify Response with FILE_NOTIFY_INFORMATION structures
            output_buffer = response["data"].get_value()

            # Parse the buffer to extract individual file change notifications
            notifications = parse_notify_buffer(output_buffer)

            # Display the results
            if not notifications:
                print(
                    "[INFO] Notification received, but no changes could be parsed from the buffer."
                )

            # Process each notification and display it with a human-readable action name
            for action_code, filename in notifications:
                # Look up the action name, or show "UNKNOWN" with the raw code
                action_str = ACTION_MAP.get(
                    action_code, f"UNKNOWN (Code: {action_code})"
                )

                print(f"[{action_str}] {filename}")
                callback(filename, action_str)

        except KeyboardInterrupt:
            print("\nReceived interrupt signal. Stopping...")
            break
        except Exception as e:
            print(f"An error occurred in the watch loop: {e}")
            # Print full traceback for debugging purposes
            import traceback

            traceback.print_exc()
            break

    # Cleanup: Close all SMB connections properly
    print("Cleaning up connections...")
    root.close()  # Close the directory handle
    tree.disconnect()  # Disconnect from the share
    sess.disconnect()  # End the SMB session
    conn.disconnect()  # Close the TCP connection
    print("SMB file system watcher stopped.")
