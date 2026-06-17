# Archived EC2 Transition Notes

This archive records the one-time transition from unpacked bare-metal application files to container deployment. Active deployment documentation now lives in `docs/DEPLOYMENT.md` and `docs/GITHUB_ACTIONS.md`.

The former bare-metal application service and `/var/www` release directory were retained only as a short rollback bridge during first container cutover. They are not part of the current deployment model.
