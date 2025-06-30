#include "tls.h"
#include "controlplane.h"

eResult tls_inspector_t::init()
{
	tls_counters.init(&controlPlane->counter_manager);
	return eResult::success;
}

void tls_inspector_t::reload_before()
{
	generations_config.next_lock();
}

void tls_inspector_t::reload(const controlplane::base_t& base_prev,
                             const controlplane::base_t& base_next,
                             common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);
	for (const auto& [name, tls_inspector] : base_next.tls_inspectors)
	{
		tls_counters.insert(name);
	}
	for (const auto& [name, tls_inspector] : base_prev.tls_inspectors)
	{
		tls_counters.remove(name);
	}

	tls_counters.allocate();

	compile(globalbase, generations_config.next());
}

void tls_inspector_t::reload_after()
{
	tls_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
}

void tls_inspector_t::compile(common::idp::updateGlobalBase::request& globalbase,
                              tls_inspect::generation_config_t& generation_config)
{
	tls_inspector_id_t tlsId = 0;

	for (auto& [name, tls_inspector] : generation_config.config_tls_inspectors)
	{
		const auto counter_id = tls_counters.get_id(name);

		std::set<std::string> blacklist(tls_inspector.blacklist_sni.begin(), tls_inspector.blacklist_sni.end());

		tls_inspector.flow.counter_id = counter_id;
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tls_inspector_update,
		                        common::idp::updateGlobalBase::tls_inspector_update::request(tlsId,
		                                                                                     blacklist,
		                                                                                     tls_inspector.flow));
		++tlsId;
	}
}

void tls_inspector_t::counters_gc_thread()
{
	while (!flagStop)
	{
		tls_counters.gc();
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}
