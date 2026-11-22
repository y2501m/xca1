cmake_minimum_required(VERSION 3.10)

# プロジェクト名
project(xca1 LANGUAGES C CXX)

# C++の標準を設定
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ソースファイル
set(SOURCES
    src/main.cpp
    src/logger/logger.cpp
    src/analysis/analysis.cpp
    external/glad/src/glad.c
    external/imgui/imgui.cpp
    external/imgui/imgui_draw.cpp
    external/imgui/imgui_tables.cpp
    external/imgui/imgui_widgets.cpp
    external/imgui/backends/imgui_impl_glfw.cpp
    external/imgui/backends/imgui_impl_opengl3.cpp
)

# パッケージ検出
find_package(glfw3 CONFIG REQUIRED)
find_package(libzip CONFIG REQUIRED)

# 実行ファイル
add_executable(${PROJECT_NAME} ${SOURCES})

# 実行ファイル名・Windowsアプリ設定
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "ZipAnalysis"
    WIN32_EXECUTABLE TRUE
)

# インクルードディレクトリ
target_include_directories(${PROJECT_NAME} PRIVATE
    external/glad/include
    external/imgui
    external/imgui/backends
)

# ライブラリーリンク
target_link_libraries(${PROJECT_NAME} PRIVATE
    glfw
    libzip::zip
)
