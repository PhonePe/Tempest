# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

{% set obs_enabled = salt['pillar.get']('tempest:observability:enabled', True) %}

include:
  - tempest.install
  - tempest.config
  - tempest.service
{% if obs_enabled %}
  - tempest.observability
{% endif %}
