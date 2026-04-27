// ---------- DHCP Lookup ---------- //
const dhcpTab = document.getElementById('dhcpTab');

const dhcpHeader = document.createElement('h2');
dhcpHeader.textContent = 'DHCP Lookup';
dhcpTab.appendChild(dhcpHeader);

const dhcpDesc = document.createElement('p');
dhcpDesc.className = 'tab-desc';
dhcpDesc.textContent = 'Submit a DHCP lease query to the USF ITC Portal in a new tab.';
dhcpTab.appendChild(dhcpDesc);

const dhcpInfo = document.createElement('div');
dhcpInfo.className = 'ops-card';
dhcpInfo.style.marginBottom = 'var(--sp-4)';
dhcpInfo.innerHTML = `
  <h4>Notes</h4>
  <p style="font-size: 12px; color: var(--ops-text-muted); margin-bottom: 0;">
    On the first click, the ITC Portal may open with the query fields populated but not yet show the submitted results. If that happens, close the tab and click <strong>Open DHCP Results</strong> again.
  </p>
`;
dhcpTab.appendChild(dhcpInfo);

const dhcpFields = [
  { name: 'start_ip', label: 'Start IP', placeholder: 'e.g. 1.1.1.1', value: '', required: true },
  { name: 'end_ip', label: 'End IP', placeholder: 'Optional', value: '' },
  { name: 'mac', label: 'MAC Address', placeholder: 'Optional', value: '' },
  { name: 'hostname', label: 'Hostname', placeholder: 'Optional', value: '' },
  { name: 'switch_name', label: 'Switch Name', placeholder: 'Optional', value: '' },
  { name: 'port', label: 'Port', placeholder: 'Optional', value: '' },
  { name: 'ap_name', label: 'AP Name', placeholder: 'Optional', value: '' },
  { name: 'netid', label: 'NetID', placeholder: 'Optional', value: '' },
  { name: 'start_time', label: 'Start Time', placeholder: 'YYYYMMDDhhmmss', value: '', required: true },
  { name: 'end_time', label: 'End Time', placeholder: 'Optional', value: '' }
];

const dhcpGrid = document.createElement('div');
dhcpGrid.style.display = 'grid';
dhcpGrid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(240px, 1fr))';
dhcpGrid.style.gap = 'var(--sp-4)';
dhcpGrid.style.marginBottom = 'var(--sp-4)';

const dhcpInputs = {};

dhcpFields.forEach(field => {
  const wrap = document.createElement('div');

  const label = document.createElement('label');
  label.textContent = field.label;
  wrap.appendChild(label);

  const input = document.createElement('input');
  input.type = 'text';
  input.id = `dhcp_${field.name}`;
  input.name = field.name;
  input.placeholder = field.placeholder;
  input.value = field.value;
  wrap.appendChild(input);

  dhcpInputs[field.name] = input;
  dhcpGrid.appendChild(wrap);
});

dhcpTab.appendChild(dhcpGrid);

const dhcpActions = document.createElement('div');
dhcpActions.style.display = 'flex';
dhcpActions.style.flexWrap = 'wrap';
dhcpActions.style.gap = 'var(--sp-2)';
dhcpActions.style.alignItems = 'center';

const dhcpOpenBtn = document.createElement('button');
dhcpOpenBtn.className = 'action-button';
dhcpOpenBtn.textContent = 'Open DHCP Results';

const dhcpResetBtn = document.createElement('button');
dhcpResetBtn.className = 'action-button secondary';
dhcpResetBtn.textContent = 'Reset Times';

dhcpActions.appendChild(dhcpOpenBtn);
dhcpActions.appendChild(dhcpResetBtn);
dhcpTab.appendChild(dhcpActions);

const dhcpStatus = document.createElement('div');
dhcpStatus.style.marginTop = 'var(--sp-3)';
dhcpStatus.style.fontSize = '12px';
dhcpStatus.style.color = 'var(--ops-text-muted)';
dhcpStatus.textContent = 'Ready to submit a DHCP lease query.';
dhcpTab.appendChild(dhcpStatus);

function resetDhcpDefaults() {
  dhcpInputs.start_time.value = '';
  dhcpInputs.end_time.value = '';
  syncDhcpTimesFromTimestamp(false);
  dhcpStatus.style.color = 'var(--ops-text-muted)';
  dhcpStatus.textContent = 'Start Time and End Time reset from Time Convert.';
}

function collectDhcpFields() {
  const values = {};
  dhcpFields.forEach(field => {
    values[field.name] = dhcpInputs[field.name].value.trim();
  });
  values.Search = 'Search';
  return values;
}

function syncDhcpTimesFromTimestamp(updateStatus = true) {
  const derived = window.timestampDerivedValues || {};
  const startValue = derived.itcPortalStart || '';
  const endValue = derived.itcPortalEnd || '';

  dhcpInputs.start_time.value = startValue;
  dhcpInputs.end_time.value = endValue;

  if (updateStatus) {
    dhcpStatus.style.color = 'var(--ops-text-muted)';
    dhcpStatus.textContent = startValue || endValue
      ? 'Start Time and End Time synced from Time Convert.'
      : 'Waiting for Time Convert values.';
  }
}

function openDhcpResults() {
  const values = collectDhcpFields();

  if (!values.start_ip) {
    dhcpStatus.style.color = 'var(--threat-red)';
    dhcpStatus.textContent = 'Start IP is required.';
    return;
  }

  if (!/^\d{14}$/.test(values.start_time)) {
    dhcpStatus.style.color = 'var(--threat-red)';
    dhcpStatus.textContent = 'Start Time must be in YYYYMMDDhhmmss format.';
    return;
  }

  if (values.end_time && !/^\d{14}$/.test(values.end_time)) {
    dhcpStatus.style.color = 'var(--threat-red)';
    dhcpStatus.textContent = 'End Time must be blank or use YYYYMMDDhhmmss format.';
    return;
  }

  const targetName = 'socapDhcpResults';
  const resultWindow = window.open('', targetName);

  if (!resultWindow) {
    dhcpStatus.style.color = 'var(--threat-red)';
    dhcpStatus.textContent = 'Popup blocked. Allow popups for this page and try again.';
    return;
  }

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = 'https://box.net.usf.edu/cgi-bin/dhcp/lease-query.pl';
  form.target = targetName;
  form.style.display = 'none';

  Object.entries(values).forEach(([name, value]) => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  });

  document.body.appendChild(form);
  form.submit();
  form.remove();

  dhcpStatus.style.color = 'var(--threat-green)';
  dhcpStatus.textContent = 'Query submitted in a new tab.';
}

dhcpOpenBtn.addEventListener('click', openDhcpResults);
dhcpResetBtn.addEventListener('click', resetDhcpDefaults);
Object.values(dhcpInputs).forEach(input => {
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      openDhcpResults();
    }
  });
});

// ─── Bidirectional sync with KQL Internal IP ─────────────
// When the Start IP changes here, push it back to the KQL Internal IP field.
dhcpInputs.start_ip.addEventListener('input', () => {
  if (typeof window.setKqlInternalIp === 'function') {
    window.setKqlInternalIp(dhcpInputs.start_ip.value, { silent: true });
  }
});

// Exposed API so kql.js can push the Internal IP value into the Start IP field.
window.setDhcpStartIp = function(ip, opts = {}) {
  if (!dhcpInputs.start_ip) return;
  if (dhcpInputs.start_ip.value === ip) return;
  dhcpInputs.start_ip.value = ip;
  if (!opts.silent) {
    dhcpStatus.style.color = 'var(--ops-text-muted)';
    dhcpStatus.textContent = 'Start IP synced from KQL Internal IP.';
  }
};

window.refreshDhcpFromTimestamp = syncDhcpTimesFromTimestamp;
syncDhcpTimesFromTimestamp(false);
