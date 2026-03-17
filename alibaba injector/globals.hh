#include <windows.h>
#include <unordered_map>
#include <vector>
#include <string>

class c_globals {
public:
	bool active = true;
	char user_name[255] = "user";
	char pass_word[255] = "pass";

	struct ProcessInfo {
		DWORD pid;
		std::string name;
	};

	char dll_path[MAX_PATH] = "";

	std::vector<std::string> log_lines;
	std::vector<ProcessInfo> process_list;
	int selected_process_idx = -1;
};

inline c_globals globals;