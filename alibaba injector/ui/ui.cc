#include "ui.hh"
#include "../globals.hh"
#include "../xorstr.hpp"
#include <fstream>
#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"
#include <commdlg.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <time.h>
#include "custom.h"

// ui namespace variables are declared in ui.hh

void ui::render() {
    if (!globals.active) return;

    ImGui::SetNextWindowPos(ImVec2(window_pos.x, window_pos.y), ImGuiCond_Once);
    ImGui::SetNextWindowSize(ImVec2(window_size.x, window_size.y));
    ImGui::SetNextWindowBgAlpha(1.0f);

    // Main window title can stay encrypted as ImGui::Begin copies it
    ImGui::Begin(_xor_("alibaba Injector").c_str(), &globals.active, ImGuiWindowFlags_NoDecoration);
    {
        auto draw = ImGui::GetWindowDrawList();
        ImVec2 pos = ImGui::GetWindowPos();
        ImVec2 size = ImGui::GetWindowSize();

        // Title Bar - Use plain strings for DrawList to avoid "gibberish" (xorstr lifetime issues)
        draw->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + 25), ImColor(0, 0, 0), 8.0f, ImDrawFlags_RoundCornersTopLeft | ImDrawFlags_RoundCornersTopRight);
        draw->AddText(ImVec2(pos.x + 9, pos.y + 5), ImColor(accent_colour[0], accent_colour[1], accent_colour[2]), "M");
        draw->AddText(ImVec2(pos.x + 27, pos.y + 5), ImColor(200, 200, 200), "alibaba");
        draw->AddText(ImVec2(pos.x + 27 + ImGui::CalcTextSize("alibaba").x, pos.y + 5), ImColor(accent_colour[0], accent_colour[1], accent_colour[2]), ".injector");

        draw->AddLine(ImVec2(pos.x, pos.y + 25), ImVec2(pos.x + size.x, pos.y + 25), ImColor(46, 46, 46));
        draw->AddRectFilledMultiColor(ImVec2(pos.x, pos.y + 26), ImVec2(pos.x + size.x, pos.y + size.y), ImColor(15, 15, 15), ImColor(0, 0, 0), ImColor(15, 15, 15, 0), ImColor(0, 0, 0, 0));

        // Close Button
        ImGui::SetCursorPos(ImVec2(size.x - 22, 4));
        if (custom::selected("x", false)) {
            globals.active = false;
        }

        if (!ui::authenticated) {
            // Login Screen - Plain strings for reliability, encryption kept for logic
            float login_width = 250.0f;
            float block_height = 220.0f;
            ImGui::SetCursorPos(ImVec2((size.x - login_width) / 2.0f, (size.y - block_height) / 2.0f));
            ImGui::BeginGroup();
            {
                ImGui::PushItemWidth(login_width);
                ImGui::Text("Authentication Required");
                ImGui::Spacing();
                ImGui::Text("Login:");
                ImGui::InputText("##login", ui::user_input, IM_ARRAYSIZE(ui::user_input));
                ImGui::Spacing();
                ImGui::Text("Password:");
                ImGui::InputText("##pass", ui::pass_input, IM_ARRAYSIZE(ui::pass_input), ImGuiInputTextFlags_Password);
                ImGui::Spacing();
                ImGui::Spacing();
                if (ImGui::Button("Sign In", ImVec2(login_width, 40))) {
                    // Logic strings are encrypted with _xor_
                    if (strcmp(ui::user_input, _xor_("admin").c_str()) == 0 && strcmp(ui::pass_input, _xor_("adminuser123").c_str()) == 0) {
                        ui::authenticated = true;
                        ui::content_animation = 0.0f;
                        ui::tab = 0;
                    }
                }
                ImGui::PopItemWidth();
            }
            ImGui::EndGroup();
        } else {
            // Sidebar / Tabs
            ImGui::SetCursorPos(ImVec2(10, 45));
            ImGui::BeginGroup();
            {
                if (custom::selected("Dashboard", ui::tab == 0)) {
                    if (ui::tab != 0) ui::old_tab = ui::tab;
                    ui::tab = 0;
                    ui::content_animation = 0.0f;
                }
                if (custom::selected("Injector", ui::tab == 1)) {
                    if (ui::tab != 1) ui::old_tab = ui::tab;
                    ui::tab = 1;
                    ui::content_animation = 0.0f;
                }
                if (custom::selected("Settings", ui::tab == 2)) {
                    if (ui::tab != 2) ui::old_tab = ui::tab;
                    ui::tab = 2;
                    ui::content_animation = 0.0f;
                }
            }
            ImGui::EndGroup();

            ui::content_animation = ImLerp(ui::content_animation, 1.0f, 0.05f);

            ImGui::SetCursorPos(ImVec2(140, 45));
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ui::content_animation);
            ImGui::BeginChild("##content", ImVec2(size.x - 150, size.y - 55));
            {
                if (ui::tab == 0) {
                    ImGui::Text("Welcome, %s!", ui::user_input);
                    ImGui::Separator();
                    ImGui::Spacing();
                    ImGui::Text("alibaba injector by:");
                    ImGui::TextColored(ImVec4(0.4f, 0.6f, 1.0f, 1.0f), "https://t.me/+5EHmo7zE-KBlYzMy");
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                        if (ImGui::IsItemClicked()) {
                            ShellExecuteA(NULL, "open", _xor_("https://t.me/+5EHmo7zE-KBlYzMy").c_str(), NULL, NULL, SW_SHOWNORMAL);
                        }
                    }
                }
                else if (ui::tab == 1) {
                    ImGui::Text("DLL Settings");
                    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 110);
                    ImGui::InputText("##dllpath", globals.dll_path, IM_ARRAYSIZE(globals.dll_path));
                    ImGui::SameLine();
                    if (ImGui::Button("Browse", ImVec2(100, 0))) {
                        OPENFILENAMEA ofn;
                        char szFile[260] = { 0 };
                        ZeroMemory(&ofn, sizeof(ofn));
                        ofn.lStructSize = sizeof(ofn);
                        ofn.hwndOwner = NULL;
                        ofn.lpstrFile = szFile;
                        ofn.nMaxFile = sizeof(szFile);
                        ofn.lpstrFilter = "DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
                        ofn.nFilterIndex = 1;
                        ofn.lpstrFileTitle = NULL;
                        ofn.nMaxFileTitle = 0;
                        ofn.lpstrInitialDir = NULL;
                        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                        if (GetOpenFileNameA(&ofn) == TRUE) {
                            strcpy_s(globals.dll_path, szFile);
                        }
                    }

                    ImGui::Spacing();
                    ImGui::Text("Target Process");
                    if (ImGui::Button("Refresh Processes", ImVec2(ImGui::GetContentRegionAvail().x, 0))) {
                        RefreshProcessList();
                    }

                    static char search_filter[128] = "";
                    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
                    ImGui::InputTextWithHint("##Filter", "Search...", search_filter, IM_ARRAYSIZE(search_filter));

                    const char* preview = (globals.selected_process_idx >= 0 && globals.selected_process_idx < (int)globals.process_list.size()) 
                        ? globals.process_list[globals.selected_process_idx].name.c_str() 
                        : "Choose target...";

                    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
                    if (ImGui::BeginCombo("##proc_combo", preview)) {
                        for (int n = 0; n < (int)globals.process_list.size(); n++) {
                            if (search_filter[0] != '\0') {
                                if (globals.process_list[n].name.find(search_filter) == std::string::npos)
                                    continue;
                            }

                            const bool is_selected = (globals.selected_process_idx == n);
                            char item_label[300];
                            sprintf_s(item_label, "[%d] %s", globals.process_list[n].pid, globals.process_list[n].name.c_str());
                            if (ImGui::Selectable(item_label, is_selected))
                                globals.selected_process_idx = n;

                            if (is_selected)
                                ImGui::SetItemDefaultFocus();
                        }
                        ImGui::EndCombo();
                    }

                    ImGui::Spacing();
                    if (ImGui::Button("INJECT", ImVec2(ImGui::GetContentRegionAvail().x, 35))) {
                        DoInject();
                    }

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Text("Detailed Logs:");
                    ImGui::BeginChild("LogRegion", ImVec2(0, 0), true);
                    for (const auto& line : globals.log_lines) {
                        ImVec4 color = ImVec4(1, 1, 1, 1);
                        if (line.find("[+]") != std::string::npos) color = ImVec4(0, 1, 0, 1);
                        else if (line.find("[!]") != std::string::npos) color = ImVec4(1, 0, 0, 1);
                        else if (line.find("[*]") != std::string::npos) color = ImVec4(0, 1, 1, 1);
                        ImGui::TextColored(color, line.c_str());
                    }
                    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                        ImGui::SetScrollHereY(1.0f);
                    ImGui::EndChild();
                }
                else if (ui::tab == 2) {
                    ImGui::Text("User Settings");
                    ImGui::Separator();
                    ImGui::Spacing();
                    ImGui::Text("UI Accent Color");
                    ImGui::ColorEdit4("##Accent", accent_colour, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);
                    ImGui::SameLine();
                    if (ImGui::Button("Reset Defaults")) {
                        accent_colour[0] = 173 / 255.f;
                        accent_colour[1] = 57 / 255.f;
                        accent_colour[2] = 57 / 255.f;
                    }
                    
                    ImGui::Spacing();
                    if (ImGui::Button("Logout")) {
                        ui::authenticated = false;
                        memset(ui::pass_input, 0, sizeof(ui::pass_input));
                    }
                }
            }
            ImGui::EndChild();
            ImGui::PopStyleVar();
        }
    }
    ImGui::End();
}

void ui::init(LPDIRECT3DDEVICE9 device) {
    dev = device;
    applyColorScheme();

    if (window_pos.x == 0) {
        RECT screen_rect{};
        GetWindowRect(GetDesktopWindow(), &screen_rect);
        screen_res = ImVec2(float(screen_rect.right), float(screen_rect.bottom));
        window_pos = (screen_res - window_size) * 0.5f;
    }
}

void ui::applyColorScheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 0.70f);
    colors[ImGuiCol_WindowBg] = ImVec4(0.07f, 0.07f, 0.07f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_Border] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.29f, 0.48f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.00f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_CheckMark] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_SliderGrab] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.57f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_Button] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_ButtonHovered] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], 0.70f);
    colors[ImGuiCol_ButtonActive] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], 0.50f);
    colors[ImGuiCol_Header] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_HeaderHovered] = ImVec4(accent_colour[0], accent_colour[1], accent_colour[2], accent_colour[3]);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
    colors[ImGuiCol_Separator] = colors[ImGuiCol_Border];
    colors[ImGuiCol_SeparatorHovered] = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
    colors[ImGuiCol_ResizeGrip] = ImVec4(0.26f, 0.59f, 0.98f, 0.20f);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);

    style.WindowRounding = 8.0f;
    style.ChildRounding = 5.0f;
    style.FrameRounding = 5.0f;
    style.PopupRounding = 5.0f;
    style.ScrollbarRounding = 5.0f;
}
