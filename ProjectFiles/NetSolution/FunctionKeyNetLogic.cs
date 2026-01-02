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

    private LowLevelKeyboardProc keyboardHookCallback;
    private IntPtr hookId = IntPtr.Zero;
    private bool isWindows;
    private System.Collections.Concurrent.ConcurrentQueue<string> keyPressQueue;
    private PeriodicTask processingTask;

    public override void Start()
    {
        // Detect platform
        isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        
        if (isWindows)
        {
            // Initialize queue for thread-safe key press handling
            keyPressQueue = new System.Collections.Concurrent.ConcurrentQueue<string>();
            
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
            
            // Check if this key is one of our function keys (fast dictionary lookup)
            if (FunctionKeys.ContainsKey(vkCode))
            {
                // Queue for processing on another thread - DO NOT process here
                // This keeps the hook callback fast and prevents system keyboard lag
                keyPressQueue.Enqueue(FunctionKeys[vkCode]);
            }
        }
        
        // Always call the next hook in the chain immediately
        return CallNextHookEx(hookId, nCode, wParam, lParam);
    }
    
    // Process queued key presses on a separate thread (not the hook callback)
    private void ProcessKeyPressQueue()
    {
        while (keyPressQueue.TryDequeue(out string keyName))
        {
            // Now safe to do logging and variable updates off the hook thread
            LogFunctionKeyPress(keyName);
        }
    }

    private void LogFunctionKeyPress(string keyName)
    {
        Log.Info("FunctionKeyNetLogic", $"Function key pressed: {keyName}");
        var lastFunctionKeyPressed = LogicObject.GetVariable("LastFunctionKeyPressed");
        lastFunctionKeyPressed.Value = keyName;
    }

}
