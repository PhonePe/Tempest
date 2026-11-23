# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

{% from "tempest/map.jinja" import tempest with context %}
{% set service = tempest.service %}
{% set paths = tempest.paths %}

include:
  - tempest.install
  - tempest.config

tempest-systemd-unit:
  file.managed:
    - name: /etc/systemd/system/{{ service.name }}.service
    - source: salt://tempest/files/tempest.service.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: tempest-config

tempest-systemd-daemon-reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: tempest-systemd-unit

tempest-service:
  service.running:
    - name: {{ service.name }}
    - enable: {{ service.enabled | lower }}
    - require:
      - file: tempest-systemd-unit
      - cmd: tempest-systemd-daemon-reload
    - watch:
      - file: tempest-config
      - file: tempest-systemd-unit
{% if tempest.environment.manage %}
      - file: tempest-environment-file
{% endif %}
