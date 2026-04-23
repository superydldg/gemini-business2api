from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from fastapi import Body, FastAPI, HTTPException, Request


@dataclass(frozen=True)
class AccountRouteDeps:
    bulk_delete_accounts: Callable[..., tuple[Any, int, list[str]]]
    bulk_update_account_disabled_status: Callable[[list[str], bool, Any], tuple[int, list[str]]]
    delete_account: Callable[..., Any]
    format_account_expiration: Callable[[Any], tuple[str, str, str]]
    get_global_stats: Callable[[], dict[str, Any]]
    get_http_client: Callable[[], Any]
    get_multi_account_mgr: Callable[[], Any]
    get_retry_policy: Callable[[], Any]
    get_session_cache_ttl_seconds: Callable[[], int]
    get_user_agent: Callable[[], str]
    load_accounts_from_source: Callable[[], list[Any]]
    logger: logging.Logger
    require_login: Callable[..., Callable]
    save_account_cooldown_state: Callable[[str, Any], Awaitable[Any]]
    set_multi_account_mgr: Callable[[Any], None]
    update_account_disabled_status: Callable[[str, bool, Any], Any]
    update_accounts_config: Callable[..., Any]


def _build_account_state(
    account_manager: Any,
    status: str,
    remaining_hours: Any,
    cooldown_seconds: int,
    cooldown_reason: str | None,
    quota_status: dict[str, Any],
) -> dict[str, Any]:
    account_config = account_manager.config
    disabled_reason = (
        getattr(account_manager, "disabled_reason", None)
        or getattr(account_config, "disabled_reason", None)
    )

    state = {
        "code": "active",
        "label": "Active",
        "severity": "success",
        "reason": None,
        "cooldown_seconds": cooldown_seconds,
        "can_enable": False,
        "can_disable": True,
        "can_delete": True,
    }

    if account_config.disabled:
        is_access_restricted = bool(disabled_reason and "403" in disabled_reason)
        state.update({
            "code": "access_restricted" if is_access_restricted else "manual_disabled",
            "label": "Access restricted" if is_access_restricted else "Manual disabled",
            "severity": "danger" if is_access_restricted else "muted",
            "reason": disabled_reason,
            "can_enable": True,
            "can_disable": False,
        })
        return state

    if account_config.is_expired():
        state.update({
            "code": "expired",
            "label": "Expired",
            "severity": "danger",
            "reason": status,
            "can_disable": False,
        })
        return state

    if cooldown_seconds > 0:
        state.update({
            "code": "rate_limited",
            "label": "Rate limited",
            "severity": "warning",
            "reason": cooldown_reason,
            "can_enable": True,
        })
        return state

    if quota_status.get("limited_count", 0) > 0:
        state.update({
            "code": "quota_limited",
            "label": "Quota limited",
            "severity": "warning",
            "reason": "quota_limited",
        })
        return state

    if remaining_hours is not None and 0 < remaining_hours < 3:
        state.update({
            "code": "expiring_soon",
            "label": "Expiring soon",
            "severity": "warning",
            "reason": status,
        })
        return state

    if not account_manager.is_available:
        state.update({
            "code": "unavailable",
            "label": "Unavailable",
            "severity": "warning",
            "reason": status,
            "can_enable": True,
        })
        return state

    return state


def register_account_routes(app: FastAPI, deps: AccountRouteDeps) -> None:
    @app.get("/admin/accounts")
    @deps.require_login()
    async def admin_get_accounts(request: Request):
        accounts_info = []
        multi_account_mgr = deps.get_multi_account_mgr()

        for account_manager in multi_account_mgr.accounts.values():
            account_config = account_manager.config
            remaining_hours = account_config.get_remaining_hours()
            status, _, remaining_display = deps.format_account_expiration(remaining_hours)
            cooldown_seconds, cooldown_reason = account_manager.get_cooldown_info()
            quota_status = account_manager.get_quota_status()
            account_state = _build_account_state(
                account_manager,
                status,
                remaining_hours,
                cooldown_seconds,
                cooldown_reason,
                quota_status,
            )

            accounts_info.append({
                "id": account_config.account_id,
                "state": account_state,
                "status": status,
                "expires_at": account_config.expires_at or "未设置",
                "remaining_hours": remaining_hours,
                "remaining_display": remaining_display,
                "is_available": account_manager.is_available,
                "failure_count": account_manager.failure_count,
                "disabled": account_config.disabled,
                "disabled_reason": getattr(account_manager, "disabled_reason", None) or getattr(account_config, "disabled_reason", None),
                "cooldown_seconds": cooldown_seconds,
                "cooldown_reason": cooldown_reason,
                "conversation_count": account_manager.conversation_count,
                "session_usage_count": account_manager.session_usage_count,
                "quota_status": quota_status,
                "trial_end": account_config.trial_end,
                "trial_days_remaining": account_config.get_trial_days_remaining(),
            })

        return {"total": len(accounts_info), "accounts": accounts_info}

    @app.get("/admin/accounts-config")
    @deps.require_login()
    async def admin_get_config(request: Request):
        try:
            accounts_data = deps.load_accounts_from_source()
            return {"accounts": accounts_data}
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 获取配置失败: {str(exc)}")
            raise HTTPException(500, f"获取失败: {str(exc)}") from exc

    @app.put("/admin/accounts-config")
    @deps.require_login()
    async def admin_update_config(request: Request, accounts_data: list[Any] = Body(...)):
        try:
            multi_account_mgr = deps.update_accounts_config(
                accounts_data,
                deps.get_multi_account_mgr(),
                deps.get_http_client(),
                deps.get_user_agent(),
                deps.get_retry_policy(),
                deps.get_session_cache_ttl_seconds(),
                deps.get_global_stats(),
            )
            deps.set_multi_account_mgr(multi_account_mgr)
            return {
                "status": "success",
                "message": "配置已更新",
                "account_count": len(multi_account_mgr.accounts),
            }
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 更新配置失败: {str(exc)}")
            raise HTTPException(500, f"更新失败: {str(exc)}") from exc

    @app.delete("/admin/accounts/{account_id}")
    @deps.require_login()
    async def admin_delete_account(request: Request, account_id: str):
        try:
            multi_account_mgr = deps.delete_account(
                account_id,
                deps.get_multi_account_mgr(),
                deps.get_http_client(),
                deps.get_user_agent(),
                deps.get_retry_policy(),
                deps.get_session_cache_ttl_seconds(),
                deps.get_global_stats(),
            )
            deps.set_multi_account_mgr(multi_account_mgr)
            return {
                "status": "success",
                "message": f"账户 {account_id} 已删除",
                "account_count": len(multi_account_mgr.accounts),
            }
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 删除账户失败: {str(exc)}")
            raise HTTPException(500, f"删除失败: {str(exc)}") from exc

    @app.put("/admin/accounts/bulk-delete")
    @deps.require_login()
    async def admin_bulk_delete_accounts(request: Request, account_ids: list[str] = Body(...)):
        if len(account_ids) > 50:
            raise HTTPException(400, f"单次最多删除 50 个账户，当前请求 {len(account_ids)} 个")
        if not account_ids:
            raise HTTPException(400, "账户ID列表不能为空")

        try:
            multi_account_mgr, success_count, errors = deps.bulk_delete_accounts(
                account_ids,
                deps.get_multi_account_mgr(),
                deps.get_http_client(),
                deps.get_user_agent(),
                deps.get_retry_policy(),
                deps.get_session_cache_ttl_seconds(),
                deps.get_global_stats(),
            )
            deps.set_multi_account_mgr(multi_account_mgr)
            return {"status": "success", "success_count": success_count, "errors": errors}
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 批量删除账户失败: {str(exc)}")
            raise HTTPException(500, f"删除失败: {str(exc)}") from exc

    @app.put("/admin/accounts/{account_id}/disable")
    @deps.require_login()
    async def admin_disable_account(request: Request, account_id: str):
        try:
            multi_account_mgr = deps.update_account_disabled_status(
                account_id,
                True,
                deps.get_multi_account_mgr(),
            )
            deps.set_multi_account_mgr(multi_account_mgr)

            if account_id in multi_account_mgr.accounts:
                account_mgr = multi_account_mgr.accounts[account_id]
                await deps.save_account_cooldown_state(account_id, account_mgr)

            return {
                "status": "success",
                "message": f"账户 {account_id} 已禁用",
                "account_count": len(multi_account_mgr.accounts),
            }
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 禁用账户失败: {str(exc)}")
            raise HTTPException(500, f"禁用失败: {str(exc)}") from exc

    @app.put("/admin/accounts/{account_id}/enable")
    @deps.require_login()
    async def admin_enable_account(request: Request, account_id: str):
        try:
            multi_account_mgr = deps.update_account_disabled_status(
                account_id,
                False,
                deps.get_multi_account_mgr(),
            )
            deps.set_multi_account_mgr(multi_account_mgr)

            if account_id in multi_account_mgr.accounts:
                account_mgr = multi_account_mgr.accounts[account_id]
                account_mgr.quota_cooldowns = {}
                deps.logger.info(f"[CONFIG] 账户 {account_id} 冷却状态已重置")
                await deps.save_account_cooldown_state(account_id, account_mgr)

            return {
                "status": "success",
                "message": f"账户 {account_id} 已启用",
                "account_count": len(multi_account_mgr.accounts),
            }
        except Exception as exc:
            deps.logger.error(f"[CONFIG] 启用账户失败: {str(exc)}")
            raise HTTPException(500, f"启用失败: {str(exc)}") from exc

    @app.put("/admin/accounts/bulk-enable")
    @deps.require_login()
    async def admin_bulk_enable_accounts(request: Request, account_ids: list[str] = Body(...)):
        multi_account_mgr = deps.get_multi_account_mgr()
        success_count, errors = deps.bulk_update_account_disabled_status(account_ids, False, multi_account_mgr)
        for account_id in account_ids:
            if account_id in multi_account_mgr.accounts:
                multi_account_mgr.accounts[account_id].quota_cooldowns = {}
        return {"status": "success", "success_count": success_count, "errors": errors}

    @app.put("/admin/accounts/bulk-disable")
    @deps.require_login()
    async def admin_bulk_disable_accounts(request: Request, account_ids: list[str] = Body(...)):
        success_count, errors = deps.bulk_update_account_disabled_status(
            account_ids,
            True,
            deps.get_multi_account_mgr(),
        )
        return {"status": "success", "success_count": success_count, "errors": errors}
