#ifndef TABS_PERMISSIONS_H
#define TABS_PERMISSIONS_H

#include "status.h"
#include "status_column_record.h"

#include <string>
#include <vector>
#include <memory>
#include <sstream>

class Permissions : public Status {
    public:
        Permissions();
        void add_data_to_record(const std::string& data);

    private:
        const std::vector<std::string> col_names{"Qualifier", "Path To Resource", "Permissions"};
        std::shared_ptr<StatusColumnRecord> col_record;
};

#endif // TABS_PERMISSIONS_H
