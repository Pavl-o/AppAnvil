#include "permissions.h"

void Permissions::add_data_to_record(const std::string& data) {
    col_record->clear();

    std::istringstream is(data); // convert the huge input string into a string stream

    // parse out the number of each type of permission (seperated by the first 4 semicolons)
    std::string allow_len_str;
    std::getline(is, allow_len_str, ';');
    std::string deny_len_str;
    std::getline(is, deny_len_str, ';');
    std::string audit_len_str;
    std::getline(is, audit_len_str, ';');
    std::string owner_len_str;
    std::getline(is, owner_len_str, ';');

    // parse out each rule-qualified string into its own string variable for even more eventual parsing
    std::string allow;
    std::getline(is, allow, ';');
    std::string deny;
    std::getline(is, deny, ';');
	std::string audit;
    std::getline(is, audit, ';');
    std::string owner;
    std::getline(is, owner, ';');

    // add rows containing permissions that have the 'allow' rule qualifier
    std::istringstream is(allow);
    for (int i = 0; i < stoi(allow_len_str); i++) {
        std::string path;
	    std::string flags;
	    std::getline(is, path, ',');
	    std::getline(is, flags, ':');

        auto row = col_record->new_row();
        col_record->set_row_data(row, 0, path);
        col_record->set_row_data(row, 1, flags);
    }

    // add rows containing permissions that have the 'deny' rule qualifier
    std::istringstream is(deny);
    for (int i = 0; i < stoi(deny_len_str); i++) {
        std::string path;
	    std::string flags;
	    std::getline(is, path, ',');
	    std::getline(is, flags, ':');

        auto row = col_record->new_row();
        col_record->set_row_data(row, 0, path);
        col_record->set_row_data(row, 1, flags);
    }

    // add rows containing permissions that have the 'audit' rule qualifier
    std::istringstream is(audit);
    for (int i = 0; i < stoi(audit_len_str); i++) {
        std::string path;
	    std::string flags;
	    std::getline(is, path, ',');
	    std::getline(is, flags, ':');

        auto row = col_record->new_row();
        col_record->set_row_data(row, 0, path);
        col_record->set_row_data(row, 1, flags);
    }

    // add rows containing permissions that have the 'owner' rule qualifier
    std::istringstream is(owner);
    for (int i = 0; i < stoi(owner_len_str); i++) {
        std::string path;
	    std::string flags;
	    std::getline(is, path, ',');
	    std::getline(is, flags, ':');

        auto row = col_record->new_row();
        col_record->set_row_data(row, 0, path);
        col_record->set_row_data(row, 1, flags);
    }

    uint num_visible = col_record->filter_rows();
}