#pragma once

#include <map>
#include <set>
#include <string>

#include "base.h"
#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"
#include "common/result.h"
#include "module.h"

namespace tls_inspect
{

class generation_config_t
{
public:
	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		config_tls_inspectors = base_next.tls_inspectors;
	}

public:
	std::map<std::string, controlplane::tls_inspect::config_t> config_tls_inspectors;
};

} // tls_inspect

class tls_inspector_t : public module_t
{
public:
	tls_inspector_t() = default;
	~tls_inspector_t() = default;

	void reload_before() override;
	void reload(const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next,
	            common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;
	void compile(common::idp::updateGlobalBase::request& globalbase,
	             tls_inspect::generation_config_t& generation_config);

private:
	generation_manager<tls_inspect::generation_config_t> generations_config;
};
