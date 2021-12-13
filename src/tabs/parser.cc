#include "parser.h"


const std::string WHITESPACE = " \n\r\t\f\v"; // NOLINT(cert-err58-cpp)

// these are all the flags which transition the resource to a subprofile
// we want to exclude these if we're just listing path + flags as they would be duplicates
std::array<std::string, 6> exclude_flags{"Cx", "cx", "Cix", "cix", "CUx", "cux"}; // NOLINT

// removes leading whitespace as we're reading a formatted source file
std::string Parser::ltrim(const std::string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

// parses the path and flags out of the passed string stream and excludes any entries
// that have one of the six transition-to-subprofile flags (in array 'a')
std::string Parser::handle_path(std::istringstream *is) {
	std::string path;
	std::string flags;
	std::getline(*is, path, ' ');
	std::getline(*is, flags, ',');
	flags = Parser::ltrim(flags);
	auto *it = std::find_if(begin(exclude_flags), end(exclude_flags),
				[&](const std::string& s)
				{return flags.find(s) != std::string::npos; });
	if (it != end(exclude_flags)) {
		return "";
	}
	//return "path: " + path + "\tmode: " + flags + '\n';

	return path + ',' + flags + ':';
}

std::string Parser::get_perms(const std::string& filename) {
	std::cerr << "trying to open the file\n";

	std::ifstream fp(filename);
	if (!fp) {
		std::cerr << "cannot open profile for parsing\n";
		return "ERROR";
  	}

	std::cerr << "opened the file\n";

	// keep track of how many of each resource we encounter in each of the 4 rule qualifier categories
	int allow_len = 0;
	int deny_len = 0;
	int audit_len = 0;
	int owner_len = 0;

	// strings for holding tempory file input tokens
	std::string line;
	std::string token;
	std::string path;
	std::string flags;

	// strings containing the rules/permissions we need to eventually return to be parsed by caller
	std::string allow_str;
	std::string deny_str;
	std::string audit_str;
	std::string owner_str;

	// move file pointer to first '{' character
	std::getline(fp, line, '{'); 

	std::cerr << line;

	// scan every line into `line` string and check if it's a path to a resource/program with 
	// access mode flags and if it is then append it to the return string
	while (std::getline(fp, line, '\n')) {
		// remove leading whitespace such as indentation
		line = Parser::ltrim(line);

		if (line.empty() || line.at(0) == '#') {
			// Do nothing
			std::cerr << "in the empty if" << std::endl;
			continue;
		}
		else if (line.at(0) == '}') {
			std::cerr << "reached a closing bracket" << std::endl;
			// we hit a closing brace, no paths can exist between these braces so skip to the next block
			// WARNING: this assumes that every closing brace is on it's own new line (seems to be the case so far)
			std::getline(fp, line, '{');
			std::cerr << "found another opening bracket" << std::endl;
		}
		if (line.at(0) == '/') {
			// we have our path to the resource/program with no qualifier (i.e. default 'allow')
			// append to the string holding all rules with the allow qualifier
			std::istringstream is(line); // so we can use getline as a tokenizer
			allow_str += Parser::handle_path(&is);
			allow_len++;
			// left in a seperate if statement for any additions that may need to be made later
			// that would differentiate these from domain sockets that start with @	
		} else if (line.at(0) == '@') {
			// we have a UNIX domain socket which is also a path with no qualifier (i.e. default 'allow') 
			// append to the string holding all rules with the allow qualifier
			std::istringstream is(line); // so we can use getline as a tokenizer
			allow_str += Parser::handle_path(&is);
			allow_len++;
			// left in a seperate if statement for any additions that may need to be made later
			// that would differentiate these from regular paths that start with /
		} else {
			// check if the line starts with any of the 4 rule qualifiers (allow, deny, audit, owner)
			// if it does, append it to the corresponding string
			std::istringstream is(line); // so we can use getline as a tokenizer
			std::getline(is, token, ' ');
			if (token == "deny") {
				deny_str += Parser::handle_path(&is);
				deny_len++;
			} else if (token == "audit") {
				audit_str += Parser::handle_path(&is);
				audit_len++;
			} else if (token == "owner") {
				owner_str += Parser::handle_path(&is);
				owner_len++;
			} else if (token == "allow") {
				// assigned by default but should still check just in case someone explicitly declared it
				allow_str += Parser::handle_path(&is);
				allow_len++;
			}
		}
	}

	std::cerr << "concatenating the string..." << std::endl;

	std::string ret = "" + std::to_string(allow_len) + ';' + std::to_string(deny_len) + ';' + std::to_string(audit_len) + ';' + std::to_string(owner_len) + ';'
		+ allow_str + ';' + deny_str + ';' + audit_str + ';' + owner_str;

	std::cerr << ret << std::endl;

	// return one massive semicolon-seperated string where the first 4 tokens are the number of entries in each rule qualifier category
	return ret;
}
