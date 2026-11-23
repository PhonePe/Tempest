# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

{% from "tempest/map.jinja" import tempest with context %}
{% set obs = tempest.observability %}
{% set prometheus = obs.prometheus %}
{% set grafana = obs.grafana %}
{% set prometheus_config_dir = prometheus.config_path.rsplit('/', 1)[0] %}

{% if prometheus.enabled %}
{% if prometheus.install_package %}
tempest-prometheus-package:
  pkg.installed:
    - name: {{ prometheus.package_name }}
{% endif %}

tempest-prometheus-config-dir:
  file.directory:
    - name: {{ prometheus_config_dir }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

tempest-prometheus-scrape-config:
  file.managed:
    - name: {{ prometheus.config_path }}
    - source: salt://tempest/files/prometheus/tempest.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: tempest-prometheus-config-dir

{% if prometheus.manage_service %}
tempest-prometheus-service:
  service.running:
    - name: {{ prometheus.service_name }}
    - enable: True
    - watch:
      - file: tempest-prometheus-scrape-config
{% endif %}
{% endif %}

{% if grafana.enabled %}
{% if grafana.install_package %}
tempest-grafana-package:
  pkg.installed:
    - name: {{ grafana.package_name }}
{% endif %}

tempest-grafana-datasource-dir:
  file.directory:
    - name: {{ grafana.provisioning_dir }}/datasources
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

tempest-grafana-dashboard-provider-dir:
  file.directory:
    - name: {{ grafana.provisioning_dir }}/dashboards
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

tempest-grafana-dashboard-dir:
  file.directory:
    - name: {{ grafana.dashboard_dir }}
    - user: {{ grafana.user }}
    - group: {{ grafana.group }}
    - mode: '0755'
    - makedirs: True
{% if grafana.install_package %}
    - require:
      - pkg: tempest-grafana-package
{% endif %}

tempest-grafana-datasource:
  file.managed:
    - name: {{ grafana.provisioning_dir }}/datasources/tempest-prometheus.yml
    - source: salt://tempest/files/grafana/datasource.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: tempest-grafana-datasource-dir

tempest-grafana-dashboard-provider:
  file.managed:
    - name: {{ grafana.provisioning_dir }}/dashboards/tempest.yml
    - source: salt://tempest/files/grafana/dashboard-provider.yml.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: tempest-grafana-dashboard-provider-dir

tempest-grafana-dashboard:
  file.managed:
    - name: {{ grafana.dashboard_dir }}/tempest-dashboard.json
    - source: {{ grafana.dashboard_source }}
    - user: {{ grafana.user }}
    - group: {{ grafana.group }}
    - mode: '0644'
    - require:
      - file: tempest-grafana-dashboard-dir

{% if grafana.manage_service %}
tempest-grafana-service:
  service.running:
    - name: {{ grafana.service_name }}
    - enable: True
    - watch:
      - file: tempest-grafana-datasource
      - file: tempest-grafana-dashboard-provider
      - file: tempest-grafana-dashboard
{% endif %}
{% endif %}
