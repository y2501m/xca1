#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui.h>
#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include "logger/logger.hpp"
#include "analysis/analysis.hpp"
#include "imgui_spinner.hpp"

static std::atomic<bool> g_isAnalyzing{false};
static std::string g_selectedFile;
static std::string g_dropError;
static std::string g_resultPassword;

void onFileDrop(GLFWwindow* window, int count, const char** paths);
void drawMainWindow();
void drawCenteredBigPassword(const std::string& password);

/*
 * ウィンドウにZIPファイルがドロップされたときに呼び出される。
 * GLFWのドロップコールバックは、glfwPollEvents()内で実行される。
 */
void onFileDrop(GLFWwindow* /*window*/, int count, const char** paths) {
    if (g_isAnalyzing.load()) {
        g_dropError = "Cannot change ZIP files while analyzing.";
        return;
    }

    // 新しいドロップが行われたら、前回の選択・解析結果を破棄する。
    // 不正なファイルだった場合、以前のファイルパスが残らないようにする。
    g_selectedFile.clear();
    g_resultPassword.clear();
    g_dropError.clear();

    if (count != 1 || paths == nullptr || paths[0] == nullptr) {
        g_dropError = "Please drop exactly one ZIP file.";
        return;
    }

    // GLFWが返すパスはUTF-8。日本語を含むWindowsパスも検証できるようにする。
    const std::string droppedPath = paths[0];
    const std::filesystem::path filePath = std::filesystem::u8path(droppedPath);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(filePath, ec)) {
        g_dropError = "The dropped item is not a readable file.";
        return;
    }

    std::string extension = filePath.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (extension != ".zip") {
        g_dropError = "Only .zip files are supported.";
        return;
    }

    g_selectedFile = droppedPath;
    g_dropError.clear();
    g_resultPassword.clear();
    Logger::getInstance().log(LogLevel::Info, "Selected ZIP file: " + g_selectedFile);
}

/*
 * メイン関数
 */
int main() {
    Logger::getInstance().log(LogLevel::Info, "Application started");

    if (!glfwInit()) {
        Logger::getInstance().log(LogLevel::Error, "Failed to initialize GLFW");
        return 1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    const int window_width = 1280;
    const int window_height = 720;

    GLFWwindow* window = glfwCreateWindow(
            window_width, window_height, "ZIP File Password Analysis", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        return 1;
    }

    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
    if (monitor != nullptr) {
        const GLFWvidmode* mode = glfwGetVideoMode(monitor);
        if (mode != nullptr) {
            glfwSetWindowPos(window,
                    (mode->width - window_width) / 2,
                    (mode->height - window_height) / 2);
        }
    }

    glfwMakeContextCurrent(window);

    // GLADの関数ポインタを初期化してからOpenGL関数を呼び出す。
    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress)) {
        Logger::getInstance().log(LogLevel::Error, "Failed to initialize GLAD");
        glfwDestroyWindow(window);
        glfwTerminate();
        return 1;
    }

    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    ImGui::StyleColorsDark();

    // GLFWのウィンドウ全体でファイルのドラッグ＆ドロップを受け取る。
    glfwSetDropCallback(window, onFileDrop);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin(
            "Password Analysis Window", nullptr,
            ImGuiWindowFlags_NoDecoration |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoSavedSettings);

        drawMainWindow();
        ImGui::End();

        ImGui::Render();
        int display_w = 0, display_h = 0;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.08f, 0.08f, 0.09f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    Logger::getInstance().log(LogLevel::Info, "Application stopped");
    return 0;
}

/*
 * ZIPファイル指定・解析画面
 */
void drawMainWindow() {
    static int maxPasswordLen = 1;
    static std::shared_ptr<Analysis> analysis;

    // ファイルはGLFWのドロップコールバックでウィンドウ全体から受け付ける。
    // 専用のドラッグ＆ドロップ領域は描画しない。
    ImGui::TextUnformatted("Drop a ZIP file anywhere in this window");

    // 最大パスワード長
    ImGui::BeginDisabled(g_isAnalyzing.load());
    ImGui::SliderInt("Max Length", &maxPasswordLen, 1, 16);
    ImGui::EndDisabled();

    // ドロップしたファイルのパスとエラーは最大パスワード長の下に表示する。
    if (!g_selectedFile.empty()) {
        ImGui::TextWrapped("File Path: %s", g_selectedFile.c_str());
    }
    if (!g_dropError.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                           "%s", g_dropError.c_str());
    }

    // ZIPが選択された後だけ解析ボタンを表示する。
    if (!g_selectedFile.empty()) {
        ImGui::BeginDisabled(g_isAnalyzing.load());
        if (ImGui::Button("Analyze Passwords")) {
            // 解析を開始できたら、以前のドロップエラーを非表示にする。
            g_dropError.clear();
            Logger::getInstance().log(LogLevel::Info,
                                      "Analyzing passwords from file: " + g_selectedFile);

            analysis = std::make_shared<Analysis>(g_selectedFile, maxPasswordLen);
            g_resultPassword.clear();
            g_isAnalyzing.store(true);

            // 解析は従来どおりバックグラウンドで実行する。
            // shared_ptrで解析オブジェクトの寿命をスレッド終了まで保持する。
            std::thread([currentAnalysis = analysis]() {
                g_resultPassword = currentAnalysis->run();
                g_isAnalyzing.store(false);
            }).detach();
        }
        ImGui::EndDisabled();
    }

    if (g_isAnalyzing.load() && analysis) {
        ImGui::TextUnformatted("Analyzing password...");
        ImGui::SameLine();
        Spinner("##spinner", 8.0f, 3);

        const uint64_t tried = analysis->triedCount.load();
        const uint64_t total = analysis->totalCount;
        const float progress = total > 0
            ? static_cast<float>(tried) / static_cast<float>(total)
            : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(-1, 0));
    }

    if (!g_isAnalyzing.load() && !g_resultPassword.empty()) {
        drawCenteredBigPassword(g_resultPassword);
    }
}

/*
 * 解析成功したパスワードを画面中央に大きく表示する
 */
void drawCenteredBigPassword(const std::string& password) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetWindowFontScale(4.0f);

    const ImVec2 textSize = ImGui::CalcTextSize(password.c_str());
    ImGui::SetCursorPos(ImVec2(
            (io.DisplaySize.x - textSize.x) * 0.5f,
            (io.DisplaySize.y - textSize.y) * 0.5f));

    ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "%s", password.c_str());
    ImGui::SetWindowFontScale(1.0f);
}
