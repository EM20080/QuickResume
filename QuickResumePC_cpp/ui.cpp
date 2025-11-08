#include "imgui.h"
#include <string>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <commdlg.h>

struct ProcessInfo
{
    int pid;
    std::string name;
    std::string path;
    bool isSystem;
};

struct AppState
{
    std::vector<ProcessInfo> processes;
    int selectedProcessIndex;
    char statusMessage[512];
    bool hideSystemProcesses;
    bool optionSuspendThreads;
    bool optionSkipExecutable;
    bool isRefreshing;
    bool isDumping;
    bool isLoading;
    bool needsProcessRefresh;
};

std::vector<ProcessInfo> GetProcessList(bool hideSystemProcesses);
bool DumpProcess(int pid, const char* outputPath, bool suspendThreads, std::string& outMessage);
bool LoadRamState(int pid, const char* inputPath, bool suspendThreads, bool skipExecutable, std::string& outMessage);

static bool SaveFileDialog(char* outPath, size_t outPathSize, const char* filter, const char* defaultExt, const char* defaultName)
{
    OPENFILENAMEA ofn;
    char szFile[260] = { 0 };
    
    if (defaultName)
        strncpy_s(szFile, defaultName, sizeof(szFile) - 1);

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrDefExt = defaultExt;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameA(&ofn) == TRUE)
    {
        strncpy_s(outPath, outPathSize, szFile, outPathSize - 1);
        return true;
    }
    return false;
}

static bool OpenFileDialog(char* outPath, size_t outPathSize, const char* filter)
{
    OPENFILENAMEA ofn;
    char szFile[260] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn) == TRUE)
    {
        strncpy_s(outPath, outPathSize, szFile, outPathSize - 1);
        return true;
    }
    return false;
}

void RenderUI(AppState& state)
{
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | 
                                   ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

    ImGui::Begin("QuickResumePC", nullptr, window_flags);

    float titleWidth = ImGui::CalcTextSize("QuickResumePC - Quick Resume for Windows").x;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - titleWidth) * 0.5f);
    ImGui::Text("QuickResumePC - Quick Resume for Windows");
    
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginGroup();
    
    bool canRefresh = !state.isRefreshing && !state.isDumping && !state.isLoading;
    if (!canRefresh)
        ImGui::BeginDisabled();
    
    if (ImGui::Button("Refresh Process List", ImVec2(180, 0)))
    {
        state.needsProcessRefresh = true;
        state.isRefreshing = true;
        strcpy_s(state.statusMessage, "Loading processes...");
    }
    
    if (!canRefresh)
        ImGui::EndDisabled();

    ImGui::SameLine();
    
    if (ImGui::Checkbox("Hide System Processes", &state.hideSystemProcesses))
    {
        state.needsProcessRefresh = true;
    }

    ImGui::SameLine();
    ImGui::Dummy(ImVec2(50, 0));
    ImGui::SameLine();
    
    ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "%s", state.statusMessage);

    ImGui::EndGroup();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImVec2 contentSize = ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y - 80);
    
    ImGui::BeginChild("ProcessListPanel", ImVec2(contentSize.x * 0.5f, contentSize.y), true);
    
    ImGui::Text("Processes (%d)", (int)state.processes.size());
    ImGui::Separator();

    if (state.needsProcessRefresh && canRefresh)
    {
        state.processes = GetProcessList(state.hideSystemProcesses);
        state.needsProcessRefresh = false;
        state.isRefreshing = false;
        
        snprintf(state.statusMessage, sizeof(state.statusMessage), 
                "Showing %d processes", (int)state.processes.size());
    }

    if (ImGui::BeginListBox("##ProcessList", ImVec2(-FLT_MIN, -FLT_MIN)))
    {
        for (int i = 0; i < (int)state.processes.size(); i++)
        {
            const auto& proc = state.processes[i];
            char label[256];
            snprintf(label, sizeof(label), "%s (PID: %d)", proc.name.c_str(), proc.pid);
            
            bool isSelected = (state.selectedProcessIndex == i);
            if (ImGui::Selectable(label, isSelected))
            {
                state.selectedProcessIndex = i;
            }
            
            if (isSelected)
                ImGui::SetItemDefaultFocus();
            
            if (ImGui::IsItemHovered() && !proc.path.empty())
            {
                ImGui::BeginTooltip();
                ImGui::Text("Path: %s", proc.path.c_str());
                ImGui::EndTooltip();
            }
        }
        ImGui::EndListBox();
    }

    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("ActionPanel", ImVec2(0, contentSize.y), true);
    
    ImGui::Text("Actions");
    ImGui::Separator();
    ImGui::Spacing();

    bool hasSelection = state.selectedProcessIndex >= 0 && 
                       state.selectedProcessIndex < (int)state.processes.size();
    bool canDump = canRefresh && hasSelection;
    bool canLoad = canRefresh && hasSelection;

    if (hasSelection)
    {
        const auto& proc = state.processes[state.selectedProcessIndex];
        ImGui::Text("Selected Process:");
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "  %s", proc.name.c_str());
        ImGui::Text("  PID: %d", proc.pid);
        if (!proc.path.empty())
        {
            ImGui::Text("  Path:");
            ImGui::TextWrapped("    %s", proc.path.c_str());
        }
    }
    else
    {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No process selected");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Options:");
    ImGui::Checkbox("Suspend Threads During Operation", &state.optionSuspendThreads);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Pause process threads for consistent memory snapshots");
    
    ImGui::Checkbox("Skip Executable Regions (Load Only)", &state.optionSkipExecutable);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Don't restore code sections - may improve stability");

    ImGui::Spacing();
    
    if (ImGui::CollapsingHeader("Quick Save/Load Tips"))
    {
        ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x);
        ImGui::TextColored(ImVec4(0.7f, 0.9f, 1.0f, 1.0f), "For best results:");
        ImGui::BulletText("Create a 'baseline' save right after starting the app");
        ImGui::BulletText("Make multiple saves at different points");
        ImGui::BulletText("Load back into the SAME process (don't restart)");
        ImGui::BulletText("If load fails, try 'Skip Executable Regions'");
        ImGui::BulletText("Games work best - system apps may be unstable");
        ImGui::PopTextWrapPos();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (!canDump)
        ImGui::BeginDisabled();
    
    if (ImGui::Button("Dump RAM State", ImVec2(-FLT_MIN, 40)))
    {
        const auto& proc = state.processes[state.selectedProcessIndex];
        
        char defaultName[256];
        SYSTEMTIME st;
        GetLocalTime(&st);
        snprintf(defaultName, sizeof(defaultName), "%s_%d_%04d%02d%02d_%02d%02d%02d.QuickResume",
                proc.name.c_str(), proc.pid,
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
        
        char savePath[512] = { 0 };
        if (SaveFileDialog(savePath, sizeof(savePath), 
            "Quick Resume State (*.QuickResume)\0*.QuickResume\0All Files (*.*)\0*.*\0",
            "QuickResume", defaultName))
        {
            state.isDumping = true;
            snprintf(state.statusMessage, sizeof(state.statusMessage),
                    "Dumping process %s (PID %d)...", proc.name.c_str(), proc.pid);
            
            std::string message;
            bool success = DumpProcess(proc.pid, savePath, state.optionSuspendThreads, message);
            
            if (success)
            {
                WIN32_FILE_ATTRIBUTE_DATA fileInfo;
                if (GetFileAttributesExA(savePath, GetFileExInfoStandard, &fileInfo))
                {
                    ULARGE_INTEGER fileSize;
                    fileSize.LowPart = fileInfo.nFileSizeLow;
                    fileSize.HighPart = fileInfo.nFileSizeHigh;
                    
                    snprintf(state.statusMessage, sizeof(state.statusMessage),
                            "Success: %s (%.2f MB)", message.c_str(), 
                            fileSize.QuadPart / (1024.0 * 1024.0));
                }
                else
                {
                    snprintf(state.statusMessage, sizeof(state.statusMessage),
                            "Success: %s", message.c_str());
                }
            }
            else
            {
                snprintf(state.statusMessage, sizeof(state.statusMessage),
                        "Failed: %s", message.c_str());
            }
            
            state.isDumping = false;
        }
        else
        {
            strcpy_s(state.statusMessage, "Dump cancelled");
        }
    }
    
    if (!canDump)
        ImGui::EndDisabled();

    ImGui::Spacing();

    if (!canLoad)
        ImGui::BeginDisabled();
    
    if (ImGui::Button("Load RAM State", ImVec2(-FLT_MIN, 40)))
    {
        const auto& proc = state.processes[state.selectedProcessIndex];
        
        char loadPath[512] = { 0 };
        if (OpenFileDialog(loadPath, sizeof(loadPath),
            "Quick Resume State (*.QuickResume)\0*.QuickResume\0All Files (*.*)\0*.*\0"))
        {
            state.isLoading = true;
            snprintf(state.statusMessage, sizeof(state.statusMessage),
                    "Loading state into process %s (PID %d)...", proc.name.c_str(), proc.pid);
            
            std::string message;
            bool success = LoadRamState(proc.pid, loadPath, 
                                       state.optionSuspendThreads, 
                                       state.optionSkipExecutable, 
                                       message);
            
            if (success)
            {
                snprintf(state.statusMessage, sizeof(state.statusMessage),
                        "Success: %s", message.c_str());
                
                MSG msg;
                for (int i = 0; i < 50; i++)
                {
                    if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
                    {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                    else
                    {
                        break;
                    }
                }
            }
            else
            {
                snprintf(state.statusMessage, sizeof(state.statusMessage),
                        "Failed: %s", message.c_str());
            }
            
            state.isLoading = false;
        }
        else
        {
            strcpy_s(state.statusMessage, "Load cancelled");
        }
    }
    
    if (!canLoad)
        ImGui::EndDisabled();

    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text("QuickResumePC v1.0 | Run as Administrator for best results");

    ImGui::End();
}