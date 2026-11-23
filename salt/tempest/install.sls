# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

{% from "tempest/map.jinja" import tempest with context %}
{% set install = tempest.install %}

tempest-group:
  group.present:
    - name: {{ tempest.group }}
    - system: True

tempest-user:
  user.present:
    - name: {{ tempest.user }}
    - gid: {{ tempest.group }}
    - home: {{ tempest.home }}
    - shell: {{ tempest.shell | default('/usr/sbin/nologin') }}
    - system: True
    - createhome: False
    - require:
      - group: tempest-group

tempest-home-dir:
  file.directory:
    - name: {{ tempest.home }}
    - user: {{ tempest.user }}
    - group: {{ tempest.group }}
    - mode: '0750'
    - require:
      - user: tempest-user

{% if install.method == 'release' %}
{% set release = install.release %}
{% set archive = 'tempest-' ~ release.version ~ '-' ~ release.platform %}
{% if not release.version or not release.sha256 or not release.base_url %}
tempest-release-pin-required:
  test.fail_without_changes:
    - name: >-
        tempest:install:release requires base_url, version, and the archive
        sha256 written beside it by make rc-linux-*; unpinned downloads are
        refused.
{% else %}
tempest-release-archive:
  archive.extracted:
    - name: {{ release.extract_dir }}/{{ release.version }}
    - source: {{ release.base_url }}/v{{ release.version }}/{{ archive }}.tar.gz
    - source_hash: sha256={{ release.sha256 }}
    - source_hash_update: True
    - user: root
    - group: root
    - enforce_toplevel: True

tempest-binary:
  file.managed:
    - name: {{ install.binary_path }}
    - source: {{ release.extract_dir }}/{{ release.version }}/{{ archive }}/tempest
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True
    - require:
      - archive: tempest-release-archive
{% endif %}
{% elif install.method == 'package' %}
tempest-package:
  pkg.installed:
    - name: {{ install.package_name }}
{% elif install.method == 'binary' %}
tempest-binary:
  file.managed:
    - name: {{ install.binary_path }}
    - source: {{ install.binary_source }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True
{% else %}
tempest-binary-managed-elsewhere:
  test.nop:
    - name: Tempest binary/package installation is managed outside this formula.
{% endif %}

{% if install.setcap %}
tempest-capability-package:
  pkg.installed:
    - name: {{ install.capability_package }}

tempest-bind-service-capability:
  cmd.run:
    - name: setcap 'cap_net_bind_service=+ep' {{ install.binary_path }}
    - unless: getcap {{ install.binary_path }} | grep -q cap_net_bind_service
    - require:
      - pkg: tempest-capability-package
{% if install.method in ('binary', 'release') %}
      - file: tempest-binary
{% elif install.method == 'package' %}
      - pkg: tempest-package
{% endif %}
{% endif %}
