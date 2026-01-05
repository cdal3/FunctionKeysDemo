#region Using directives
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using UAManagedCore;
using OpcUa = UAManagedCore.OpcUa;
using FTOptix.UI;
using FTOptix.HMIProject;
using FTOptix.NativeUI;
using FTOptix.Retentivity;
using FTOptix.CoreBase;
using FTOptix.Core;
using FTOptix.NetLogic;
#endregion

public class FunctionKeyNetLogic : BaseNetLogic
{
    // Delegate for keyboard hook callback
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    // Windows P/Invoke for keyboard hook (event-based)
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;

    // Virtual key codes for function keys (F1-F12)
    private static readonly Dictionary<int, string> FunctionKeys = new Dictionary<int, string>
    {
        { 0x70, "F1" }, { 0x71, "F2" }, { 0x72, "F3" }, { 0x73, "F4" },
        { 0x74, "F5" }, { 0x75, "F6" }, { 0x76, "F7" }, { 0x77, "F8" },
        { 0x78, "F9" }, { 0x79, "F10" }, { 0x7A, "F11" }, { 0x7B, "F12" }
    };

    // Map function key names to virtual key codes
    private static readonly Dictionary<string, int> FunctionKeyNameToVK = new Dictionary<string, int>
    {
        { "F1", 0x70 }, { "F2", 0x71 }, { "F3", 0x72 }, { "F4", 0x73 },
        { "F5", 0x74 }, { "F6", 0x75 }, { "F7", 0x76 }, { "F8", 0x77 },
        { "F9", 0x78 }, { "F10", 0x79 }, { "F11", 0x7A }, { "F12", 0x7B }
    };

    // Configurable variables
    private string targetFunctionKey;  // Which function key to listen for
    private int terminatingKeyVK;      // VK_RETURN (Enter key) by default
    
    private LowLevelKeyboardProc keyboardHookCallback;
    private IntPtr hookId = IntPtr.Zero;
    private bool isWindows;
    private System.Collections.Concurrent.ConcurrentQueue<KeyPressInfo> keyPressQueue;
    private PeriodicTask processingTask;
    
    // Text capture state
    private bool isCapturingText = false;
    private IUAVariable capturing;
    private System.Text.StringBuilder capturedText;

    // Helper class to store key press information
    private class KeyPressInfo
    {
        public int VirtualKeyCode { get; set; }
        public string KeyName { get; set; }
        public char KeyChar { get; set; }
    }

    public override void Start()
    {
        capturing = LogicObject.GetVariable("Capturing");
        
        // Init the target function key with validation
        try
        {
            string targetKeyStr = LogicObject.GetVariable("TargetFunctionKey").Value;
            if (string.IsNullOrWhiteSpace(targetKeyStr))
            {
                throw new ArgumentException("TargetFunctionKey is empty or null");
            }
            
            // Validate that it's a valid function key (F1-F12)
            if (!FunctionKeyNameToVK.ContainsKey(targetKeyStr))
            {
                throw new ArgumentException($"'{targetKeyStr}' is not a valid function key. Must be F1-F12.");
            }
            
            targetFunctionKey = targetKeyStr;
            Log.Info("FunctionKeyNetLogic", $"Target function key set to: {targetFunctionKey}");
        }
        catch (Exception ex)
        {
            Log.Error("FunctionKeyNetLogic", $"Failed to read TargetFunctionKey: {ex.Message}. Using default (F1)");
            targetFunctionKey = "F1"; // Default to F1
        }
        
        // Parse terminating key from hex string
        string terminatingKeyStr = LogicObject.GetVariable("TerminatingKey").Value;
        try
        {
            // Remove "0x" prefix if present and parse as hexadecimal
            if (terminatingKeyStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                terminatingKeyStr = terminatingKeyStr.Substring(2);
            }
            terminatingKeyVK = Convert.ToInt32(terminatingKeyStr, 16);
            Log.Info("FunctionKeyNetLogic", $"Terminating key set to: 0x{terminatingKeyVK:X}");
        }
        catch (Exception ex)
        {
            Log.Error("FunctionKeyNetLogic", $"Failed to parse TerminatingKey value '{terminatingKeyStr}': {ex.Message}. Using default (Enter - 0x0D)");
            terminatingKeyVK = 0x0D; // Default to Enter key
        }
        
        // Detect platform
        isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        
        if (isWindows)
        {
            // Initialize queue for thread-safe key press handling
            keyPressQueue = new System.Collections.Concurrent.ConcurrentQueue<KeyPressInfo>();
            capturedText = new System.Text.StringBuilder();
            
            // Store the callback as a field to prevent garbage collection
            keyboardHookCallback = HookCallback;
            
            // Install the low-level keyboard hook - this is EVENT-BASED
            // Windows will call our callback whenever ANY key is pressed system-wide
            hookId = SetHook(keyboardHookCallback);
            
            // Start a periodic task to process queued keys (off the hook thread)
            processingTask = new PeriodicTask(ProcessKeyPressQueue, 50, LogicObject);
            processingTask.Start();
            
            Log.Info("FunctionKeyNetLogic", "Started event-based function key monitoring on Windows");
        }
        else
        {
            Log.Warning("FunctionKeyNetLogic", "Event-based keyboard monitoring not implemented for Linux");
        }
    }

    public override void Stop()
    {
        // Stop processing task
        if (processingTask != null)
        {
            processingTask.Dispose();
            processingTask = null;
        }
        
        // Unhook the keyboard hook
        if (hookId != IntPtr.Zero)
        {
            UnhookWindowsHookEx(hookId);
            hookId = IntPtr.Zero;
        }
        
        Log.Info("FunctionKeyNetLogic", "Stopped function key monitoring");
    }

    private IntPtr SetHook(LowLevelKeyboardProc proc)
    {
        using (var curProcess = System.Diagnostics.Process.GetCurrentProcess())
        using (var curModule = curProcess.MainModule)
        {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    // EVENT-BASED CALLBACK: Called by Windows whenever ANY key is pressed
    // CRITICAL: Must return quickly to avoid blocking system keyboard input
    private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            // A key was pressed - extract the virtual key code
            int vkCode = Marshal.ReadInt32(lParam);
            
            // Create key press info
            var keyInfo = new KeyPressInfo
            {
                VirtualKeyCode = vkCode,
                KeyName = FunctionKeys.ContainsKey(vkCode) ? FunctionKeys[vkCode] : null,
                KeyChar = GetCharFromVirtualKey(vkCode)
            };
            
            // Queue for processing on another thread
            keyPressQueue.Enqueue(keyInfo);
        }
        
        // Always call the next hook in the chain immediately
        return CallNextHookEx(hookId, nCode, wParam, lParam);
    }
    
    // Convert virtual key code to character
    private char GetCharFromVirtualKey(int vkCode)
    {
        // For alphanumeric and special characters
        if ((vkCode >= 0x30 && vkCode <= 0x39) || // 0-9
            (vkCode >= 0x41 && vkCode <= 0x5A) || // A-Z
            (vkCode >= 0x60 && vkCode <= 0x69))   // Numpad 0-9
        {
            return (char)vkCode;
        }
        
        // Common special characters
        switch (vkCode)
        {
            case 0x20: return ' ';  // Space
            case 0xBA: return ';';  // OEM_1
            case 0xBB: return '=';  // OEM_PLUS
            case 0xBC: return ',';  // OEM_COMMA
            case 0xBD: return '-';  // OEM_MINUS
            case 0xBE: return '.';  // OEM_PERIOD
            case 0xBF: return '/';  // OEM_2
            case 0xC0: return '`';  // OEM_3
            default: return '\0';
        }
    }
    
    // Process queued key presses on a separate thread (not the hook callback)
    private void ProcessKeyPressQueue()
    {
        while (keyPressQueue.TryDequeue(out KeyPressInfo keyInfo))
        {
            // Check if this is our target function key to start capture
            if (!isCapturingText && keyInfo.KeyName == targetFunctionKey)
            {
                isCapturingText = true;
                capturing.Value = true;
                capturedText.Clear();
                Log.Info("FunctionKeyNetLogic", $"Started text capture after {targetFunctionKey} press");
            }
            // Check if this is the terminating key to end capture
            else if (isCapturingText && keyInfo.VirtualKeyCode == terminatingKeyVK)
            {
                isCapturingText = false;
                capturing.Value = false;
                string finalText = capturedText.ToString();
                Log.Info("FunctionKeyNetLogic", $"Text capture complete: {finalText}");
                
                // Store captured text in a variable
                var capturedTextVariable = LogicObject.GetVariable("CapturedText");
                if (capturedTextVariable != null)
                {
                    capturedTextVariable.Value = finalText;
                }
            }
            // If we're capturing, add the character to our buffer
            else if (isCapturingText && keyInfo.KeyChar != '\0')
            {
                capturedText.Append(keyInfo.KeyChar);
            }
        }
    }
}
