# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

{% from "tempest/map.jinja" import tempest with context %}
{% set paths = tempest.paths %}
{% set env = tempest.environment %}

include:
  - tempest.install

tempest-config-dir:
  file.directory:
    - name: {{ paths.config_dir }}
    - user: root
    - group: {{ tempest.group }}
    - mode: '0750'
    - require:
      - group: tempest-group

tempest-tftp-root:
  file.directory:
    - name: {{ paths.tftp_root }}
    - user: {{ paths.tftp_root_user }}
    - group: {{ paths.tftp_root_group }}
    - mode: '{{ paths.tftp_root_mode }}'
    - require:
      - user: tempest-user

tempest-log-dir:
  file.directory:
    - name: {{ paths.log_dir }}
    - user: {{ tempest.user }}
    - group: {{ tempest.group }}
    - mode: '0750'
    - require:
      - user: tempest-user

tempest-run-dir:
  file.directory:
    - name: {{ paths.run_dir }}
    - user: {{ tempest.user }}
    - group: {{ tempest.group }}
    - mode: '0750'
    - require:
      - user: tempest-user

tempest-config:
  file.managed:
    - name: {{ paths.config_file }}
    - source: salt://tempest/files/tempest.toml.jinja
    - template: jinja
    - user: root
    - group: {{ tempest.group }}
    - mode: '0640'
    - require:
      - file: tempest-config-dir
      - file: tempest-tftp-root
      - file: tempest-log-dir

{% if env.manage %}
tempest-environment-file:
  file.managed:
    - name: {{ paths.env_file }}
    - source: salt://tempest/files/tempest.env.jinja
    - template: jinja
    - user: root
    - group: {{ tempest.group }}
    - mode: '{{ env.mode }}'
    - require:
      - file: tempest-config-dir
{% endif %}
