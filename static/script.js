const logs_table = document.querySelector(".logs-table tbody")

async function get_logs() {
   try {
    const res = await fetch(`/API/get_ip_logs`)
    if (!res.ok) {
        throw new Error(res.status)
    }
    const json = await res.json()
    const data = json.data
    console.log(data)
    document.querySelector(".ip").textContent = `${json.ip} - stats`
    data.forEach(e => {
        if (e.endpoint === 'undefined') return
        const tr = document.createElement('tr')
        tr.innerHTML = `
            <tr>
                <td>${e.endpoint}</td>
                <td>${e.country}</td>
                <td>${e.risk_score}</td>
                <td>${e.risk_level}</td>
                <td>${e.date}</td>
            </tr>`
        if (e.risk_level === 'HIGH') {
            tr.style.borderColor = '#FF3B3B'
        }
        else if (e.risk_level === 'MEDIUM') {
            tr.style.borderColor = '#FFB020'
        }
        logs_table.appendChild(tr)
    }); 
   } 
   catch (err) {
    console.log(err)
   }
}

document.addEventListener('DOMContentLoaded', async () => {
    await get_logs()
})