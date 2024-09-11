const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));


const checkEmailValidity = async (email) => {
    const apiKey = '705e5204458a996c38152d6fdb7b3f77959b173f';
    const apiUrl = `https://api.hunter.io/v2/email-verifier?email=${email}&api_key=${apiKey}`

    try {
        const response = await fetch(apiUrl)
        const data = await response.json()

        if (data.data.status === 'valid') {
            return true
        } else {
            console.log('Email verification status:', data.data.status);
            return false
        }
    } catch (error) {
        console.error('Erreur lors de la vérification de l\'email:', error)
        return false
    }
}

module.exports = checkEmailValidity