package test.terraform.analysis

import data.terraform.analysis

test_allow_var_vpc_security_ids_as_refs if {
	false
}

test_deny_var_vpc_security_ids_as_literal if {
	false
}

test_deny_if_gp3_has_low_allocated_storage if {
	false
}

test_allow_if_gp3_has_enough_allocated_storage if {
	false
}

test_allow_db_engine_version_majour_upgrade_with_correct_prepare_flag if {
 false
}

test_deny_db_engine_version_majour_upgrade_with_incorrect_prepare_flag if {
 false
}

test_deny_if_db_engine_is_changed if {
	false
}

test_allow_if_db_instance_class_is_not_xlarge if {
	false
}

test_deny_if_db_instance_class_is_Nxlarge if {
	false
}

test_deny_if_local_db_name_changes if {
	false
}

test_deny_create_storage_type_eq_io if {
	false
}

test_deny_update_storage_type_eq_io if {
	false
}

test_deny_if_var_is_production_is_true_is_destroyed if {
	false
}

test_allow_non_prod_rds_destroy_with_deletion_protection_false if {
	false
}

test_deny_non_prod_rds_destroy_with_deletion_protection_true if {
	false
}
