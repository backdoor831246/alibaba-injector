#pragma once
#include <d3d9.h>
#include "../imgui/imgui.h"

#include <fstream>
#include <string>

namespace ui {
void init(LPDIRECT3DDEVICE9);
void render();
void applyColorScheme();
} // namespace ui

bool DoInject();
void RefreshProcessList();

namespace ui {
inline LPDIRECT3DDEVICE9 dev;
inline const char *window_title = "alibaba injector";
} // namespace ui

namespace ui {
inline ImVec2 screen_res{000, 000};
inline ImVec2 window_pos{0, 0};
inline ImVec2 window_size{650, 500};
inline DWORD window_flags =
    ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings |
    ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar;

inline int tab = 0;
inline int old_tab = 0;
inline float content_animation = 0.0f;

inline bool authenticated = false;
inline char user_input[64] = "";
inline char pass_input[64] = "";
} // namespace ui

inline float accent_colour[4] = {173 / 255.f, 57 / 255.f, 57 / 255.f, 1.0f};